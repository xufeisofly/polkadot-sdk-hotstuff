use std::sync::Arc;

use sc_authority_discovery::Service as AuthorityDiscoveryService;
use sc_client_api::Backend;
use sc_consensus_hotstuff_bls::keystore::Keystore as BlsKeystore;
use sc_network::{NotificationService, ProtocolName};
use sc_service::SpawnEssentialTaskHandle;
use sc_transaction_pool_api::TransactionPool;
use sp_authority_discovery::AuthorityDiscoveryApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_consensus::SelectChain;
use sp_consensus_hotstuff::HotstuffApi;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use tokio::sync::mpsc::channel;

use crate::block_syncer::BlockSyncerWorker;
use crate::metrics::MetricsOpt;
use crate::peer_provider::PeerProviderWorker;
use crate::qc_event_worker::QcEventWorker;
use crate::session_info_provider::SessionInfoService;
use crate::session_rotation_worker::SessionRotationWorker;
use crate::state::StateWorker;
use crate::{
    block_importer::{BlockImportService, BlockImportWorker, HotstuffCommitter, SyncEventReceiver},
    client::HotstuffClient,
    core::{NonValidatorCore, ValidatorCore},
    crypto::HotstuffCrypto,
    network::{run_gossip_task, ConsensusNetwork, HotstuffNetworkSender, Network, Syncing},
    pacemaker::Pacemaker,
    primitives::{CHANNEL_CAPACITY, MAX_TXS_LIMIT},
    proposer::Proposer,
    select_chain::SelectChainReceiver,
};

const TASK_GROUP_NAME: &str = "Hotstuff";

/// Parameters for offline block import operations (import-blocks, check-block commands).
/// This is a minimal subset of HotstuffParams without network components.
pub struct ImportWorkerParams<B, BE, C, SC>
where
    B: BlockT,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    SC: SelectChain<B> + 'static,
{
    pub client: Arc<C>,
    pub backend: Arc<BE>,
    pub block_importer_worker: BlockImportWorker<B, BE, C, SC>,
    pub block_importer_service: BlockImportService<B>,
    pub sync_event_rx: SyncEventReceiver<B>,
    pub session_info_worker: crate::session_info_provider::SessionInfoWorker<B, C>,
    pub session_info_service: Arc<SessionInfoService<B>>,
    pub spawn_handle: SpawnEssentialTaskHandle,
}

/// Spawn minimal HOTSTUFF workers required for offline block import/check operations.
///
/// This function starts only the essential workers needed for block import without
/// network or consensus components. It's used by import-blocks and check-block commands.
pub fn run_hotstuff_import_workers<B, BE, C, SC>(
    params: ImportWorkerParams<B, BE, C, SC>,
) -> sp_blockchain::Result<()>
where
    B: BlockT,
    BE: Backend<B> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    C: HotstuffClient<B, BE> + 'static,
    SC: SelectChain<B> + 'static,
{
    let ImportWorkerParams {
        client,
        backend,
        block_importer_worker,
        block_importer_service,
        sync_event_rx,
        session_info_worker,
        session_info_service,
        spawn_handle,
    } = params;

    // 1. Session info worker - provides validator session information
    spawn_handle.spawn(
        "hotstuff-session-info-worker",
        TASK_GROUP_NAME,
        async move { session_info_worker.run().await },
    );

    // 2. State worker - manages chain state for consensus
    let (state_worker, state_service) = crate::state::StateWorker::new_with_service(
        client.clone(),
        backend.clone(),
        session_info_service.clone(),
    );
    spawn_handle.spawn("hotstuff-state-worker", TASK_GROUP_NAME, async move {
        state_worker.run().await
    });

    // 3. Set up committer for block finalization
    let block_importer_service_for_committer = block_importer_service.clone();
    let state_service_for_committer = state_service.clone();
    let client_for_committer = client.clone();
    spawn_handle.spawn("hotstuff-committer-setup", TASK_GROUP_NAME, async move {
        let committer = Arc::new(crate::block_importer::HotstuffCommitter::new(
            state_service_for_committer,
            client_for_committer,
        ));
        block_importer_service_for_committer
            .set_committer(committer)
            .await;
    });

    spawn_handle.spawn_blocking(
        "hotstuff-block-importer-worker",
        TASK_GROUP_NAME,
        async move { block_importer_worker.run().await },
    );

    let (session_changed_tx, session_changed_rx) = channel(CHANNEL_CAPACITY);
    let (session_rotation_worker, session_rotation_service) =
        SessionRotationWorker::new_with_service(session_info_service.clone(), session_changed_tx);
    spawn_handle.spawn(
        "hotstuff-session-rotation-worker",
        TASK_GROUP_NAME,
        async move { session_rotation_worker.run().await },
    );
    let qc_event_worker = QcEventWorker::new(
        block_importer_service.clone(),
        state_service.clone(),
        session_rotation_service,
        sync_event_rx,
    );
    spawn_handle.spawn("hotstuff-qc-event-worker", TASK_GROUP_NAME, async move {
        qc_event_worker.run().await
    });

    // 4. Non-validator core - processes sync events for block import
    let non_validator_core: crate::core::NonValidatorCore<B, BE, C> =
        crate::core::NonValidatorCore::new(session_changed_rx);
    spawn_handle.spawn_blocking("hotstuff-non-validator-core", TASK_GROUP_NAME, async move {
        non_validator_core.run().await;
    });

    Ok(())
}

pub struct HotstuffParams<B, N, S, BE, BK, C, P, SC, CIDP>
where
    B: BlockT,
    N: Network<B> + Sync + 'static,
    S: Syncing<B> + Sync + 'static,
    BE: Backend<B> + 'static,
    BK: BlsKeystore + 'static,
    P: TransactionPool<Block = B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    SC: SelectChain<B> + 'static,
    CIDP: sp_inherents::CreateInherentDataProviders<B, ()> + 'static,
{
    pub create_inherent_data_providers: CIDP,
    pub network: N,
    pub sync: S,
    pub keystore: KeystorePtr,
    pub bls_keystore: Arc<BK>,
    pub client: Arc<C>,
    pub backend: Arc<BE>,
    pub pool: Arc<P>,
    pub notification_service: Box<dyn NotificationService>,
    pub authority_discovery_service: AuthorityDiscoveryService,
    pub select_chain: SC,
    pub best_block_request_rx: SelectChainReceiver<B>,
    pub block_importer_worker: BlockImportWorker<B, BE, C, SC>,
    pub block_importer_service: BlockImportService<B>,
    pub session_info_service: Arc<SessionInfoService<B>>,
    pub sync_event_rx: SyncEventReceiver<B>,
    pub protocol_name: ProtocolName,
    pub spawn_handle: SpawnEssentialTaskHandle,
    pub metrics: MetricsOpt,
    pub is_authority: bool,
    pub session_info_worker: crate::session_info_provider::SessionInfoWorker<B, C>,
}

pub fn run_hotstuff<B, N, S, BE, BK, C, P, SC, CIDP>(
    params: HotstuffParams<B, N, S, BE, BK, C, P, SC, CIDP>,
) -> sp_blockchain::Result<()>
where
    B: BlockT,
    N: Network<B> + Sync + 'static,
    S: Syncing<B> + Sync + 'static,
    BE: Backend<B> + 'static,
    BK: BlsKeystore + 'static,
    P: TransactionPool<Block = B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    SC: SelectChain<B> + 'static,
    CIDP: sp_inherents::CreateInherentDataProviders<B, ()> + 'static,
{
    let HotstuffParams {
        create_inherent_data_providers,
        network,
        sync,
        keystore,
        bls_keystore,
        client,
        backend,
        pool,
        notification_service,
        authority_discovery_service,
        select_chain: _,
        best_block_request_rx,
        block_importer_worker,
        block_importer_service,
        session_info_service,
        sync_event_rx,
        protocol_name,
        spawn_handle,
        metrics,
        is_authority,
        session_info_worker,
    } = params;
    spawn_handle.spawn(
        "hotstuff-session-info-worker",
        TASK_GROUP_NAME,
        async move { session_info_worker.run().await },
    );

    let (consensus_msg_tx, consensus_msg_rx) = channel(CHANNEL_CAPACITY);
    let (proposer_op_tx, proposer_op_rx) = channel(CHANNEL_CAPACITY);
    let (pacemaker_op_tx, pacemaker_op_rx) = channel(CHANNEL_CAPACITY);

    let crypto = HotstuffCrypto::new(
        keystore.clone(),
        bls_keystore.clone(),
        session_info_service.clone(),
    );

    let (gossip_sender, gossip_receiver, peer_lifecycle_rx) = run_gossip_task::<B, N, S>(
        network.clone(),
        sync.clone(),
        notification_service,
        protocol_name.clone(),
    );

    let network_sender =
        HotstuffNetworkSender::new(gossip_sender.clone(), consensus_msg_tx.clone());
    let (peer_prov_worker, peer_prov_service) = PeerProviderWorker::new_with_service(
        authority_discovery_service,
        session_info_service.clone(),
        network_sender.clone(),
    );
    let (state_worker, state_service) = StateWorker::new_with_service(
        client.clone(),
        backend.clone(),
        session_info_service.clone(),
    );

    let proposer = Proposer::new(
        create_inherent_data_providers,
        client.clone(),
        backend.clone(),
        pool.clone(),
        network_sender.clone(),
        crypto.clone(),
        MAX_TXS_LIMIT,
        session_info_service.clone(),
        metrics.clone(),
        proposer_op_rx,
    );
    let pacemaker = Pacemaker::new(network_sender.clone(), crypto.clone(), pacemaker_op_rx);

    // Set committer for block importer (for block finalization functionality)
    // Note: This must be done after state_service is created but before consensus starts
    let block_importer_service_for_committer = block_importer_service.clone();
    let state_service_for_committer = state_service.clone();
    let client_for_committer = client.clone();
    tokio::spawn(async move {
        let committer = Arc::new(HotstuffCommitter::new(
            state_service_for_committer,
            client_for_committer,
        ));
        block_importer_service_for_committer
            .set_committer(committer)
            .await;
    });

    let (block_syncer_worker, block_syncer_service) =
        BlockSyncerWorker::new_with_service(sync.clone());

    spawn_handle.spawn(
        "hotstuff-peer-provider-worker",
        TASK_GROUP_NAME,
        async move { peer_prov_worker.run().await },
    );
    spawn_handle.spawn("hotstuff-state-worker", TASK_GROUP_NAME, async move {
        state_worker.run().await
    });
    spawn_handle.spawn(
        "hotstuff-block-importer-worker",
        TASK_GROUP_NAME,
        async move { block_importer_worker.run().await },
    );

    let (session_changed_tx, session_changed_rx) = channel(CHANNEL_CAPACITY);
    let (session_rotation_worker, session_rotation_service) =
        SessionRotationWorker::new_with_service(session_info_service.clone(), session_changed_tx);
    spawn_handle.spawn(
        "hotstuff-session-rotation-worker",
        TASK_GROUP_NAME,
        async move { session_rotation_worker.run().await },
    );
    let qc_event_worker = QcEventWorker::new(
        block_importer_service.clone(),
        state_service.clone(),
        session_rotation_service.clone(),
        sync_event_rx,
    );
    spawn_handle.spawn("hotstuff-qc-event-worker", TASK_GROUP_NAME, async move {
        qc_event_worker.run().await
    });

    if is_authority {
        // Validator: full consensus with timer, messages, chain events
        let validator_core = ValidatorCore::new(
            network_sender.clone(),
            crypto.clone(),
            state_service,
            session_info_service.clone(),
            peer_prov_service,
            client.clone(),
            block_importer_service,
            block_syncer_service,
            metrics,
            consensus_msg_rx,
            proposer_op_tx,
            pacemaker_op_tx,
            best_block_request_rx,
            session_rotation_service,
            session_changed_rx,
            peer_lifecycle_rx,
        );

        let consensus_network = ConsensusNetwork::new(gossip_receiver, consensus_msg_tx);

        // session_info_worker is now spawned above if provided
        spawn_handle.spawn_blocking("sc-consensus-hotstuff network", TASK_GROUP_NAME, async {
            consensus_network.run().await
        });
        spawn_handle.spawn("hotstuff-proposer", TASK_GROUP_NAME, async move {
            proposer.run().await
        });
        spawn_handle.spawn("hotstuff-pacemaker", TASK_GROUP_NAME, async move {
            pacemaker.run().await
        });
        spawn_handle.spawn(
            "hotstuff-block-syncer-worker",
            TASK_GROUP_NAME,
            async move { block_syncer_worker.run().await },
        );
        spawn_handle.spawn_blocking(
            "sc-consensus-hotstuff worker",
            TASK_GROUP_NAME,
            async move {
                validator_core.run().await;
            },
        );
    } else {
        // Non-validator: processes sync events and session rotation
        let non_validator_core = NonValidatorCore::<B, BE, C>::new(session_changed_rx);

        spawn_handle.spawn_blocking(
            "sc-consensus-hotstuff worker",
            TASK_GROUP_NAME,
            async move {
                non_validator_core.run().await;
            },
        );
    }

    Ok(())
}
