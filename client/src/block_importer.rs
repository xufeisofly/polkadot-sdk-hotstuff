use codec::Encode;
use sc_block_builder::{BlockBuilderApi, BlockBuilderBuilder};
use sc_transaction_pool_api::TransactionValidityError;
use sp_blockchain::{ApplyExtrinsicFailed, Error as ClientError};
use sp_consensus::Error as ConsensusError;
use sp_consensus::{BlockOrigin, SelectChain};
use sp_consensus_hotstuff::consensus::{ConsensusLog, HOTSTUFF_CONSENSUS_ID};
use sp_consensus_hotstuff::hash_of;
use sp_runtime::transaction_validity::InvalidTransaction;
use sp_runtime::{Digest, DigestItem, Justifications};
use std::{marker::PhantomData, sync::Arc};

use sc_client_api::Backend;
use sc_consensus::{
    BlockCheckParams, BlockImport, BlockImportParams, BoxBlockImport, BoxJustificationImport,
    DefaultImportQueue, ForkChoiceStrategy, ImportResult, JustificationImport, StateAction,
    StorageChanges as ImportStorageChanges, Verifier,
};
use sp_blockchain::BlockStatus;
use sp_runtime::{
    traits::{Block as BlockT, Header, NumberFor, Zero},
    Justification,
};
use tokio::sync::{mpsc, oneshot};

use crate::crypto::{verify_qc_with_validator_pks, Participants, QuorumSignature};
use crate::metrics::MetricsOpt;
use crate::primitives::{LruCache, CHANNEL_CAPACITY};
use crate::session_info_provider::{
    quorum_voting_power_from_total, SessionAuthorityProvider, SessionInfoService,
};
use crate::state::{LeaderProvider, QcProvider, StateService};
use crate::{
    aux_store,
    client::HotstuffClient,
    error::{HotstuffError, HotstuffResult},
    messages::{Proposal, QC},
    primitives::opaque_exts_2_exts,
};

use prometheus_endpoint::Registry;

const LOG_TARGET: &str = "sc-consensus-hotstuff::block_importer";
const RECENT_IMPORTED_LRU_SIZE: usize = 50;
const RECENT_FINALIZED_LRU_SIZE: usize = 10;

pub type SyncEventSender<B> = mpsc::Sender<SyncEvent<B>>;
pub type SyncEventReceiver<B> = mpsc::Receiver<SyncEvent<B>>;

#[derive(Debug)]
pub enum SyncEvent<B: BlockT> {
    OnQC(Box<QC<B>>),
    OnHistoricalQC(Box<QC<B>>),
}

// Messages from Service to Worker
pub(crate) enum ServiceToWorkerMsg<B: BlockT> {
    ImportProposal(Box<Proposal<B>>, oneshot::Sender<HotstuffResult<B::Hash>>),
    ImportQc(Box<QC<B>>, oneshot::Sender<HotstuffResult<()>>),
    BlockExist(B::Hash, oneshot::Sender<HotstuffResult<()>>),
    CheckBlock(
        BlockCheckParams<B>,
        oneshot::Sender<Result<ImportResult, ConsensusError>>,
    ),
    ImportBlock(
        Box<BlockImportParams<B>>,
        oneshot::Sender<Result<ImportResult, ConsensusError>>,
    ),
    ImportJustification(
        B::Hash,
        NumberFor<B>,
        Justification,
        oneshot::Sender<Result<(), ConsensusError>>,
    ),
    TryCommit(Box<QC<B>>, oneshot::Sender<HotstuffResult<bool>>),
    SetCommitter(Arc<dyn Committer<B>>),
}

// Consensus import interface

// Legacy trait for compatibility
#[async_trait::async_trait]
pub trait ConsensusBlockImport<B>: Send + Sync
where
    B: BlockT,
{
    async fn import_proposal(&self, proposal: &Proposal<B>) -> HotstuffResult<B::Hash>;
    async fn import_qc(&self, qc: QC<B>) -> HotstuffResult<()>;
    async fn block_exist(&self, block_hash: B::Hash) -> HotstuffResult<()>;
    async fn try_commit(&self, commit_qc: &QC<B>) -> HotstuffResult<bool>;
}

// Sync import adapter

// BlockImport trait implementation for BoxBlockImport compatibility
pub struct SyncBlockImportAdapter<B: BlockT> {
    service: BlockImportService<B>,
}

impl<B: BlockT> SyncBlockImportAdapter<B> {
    pub fn new(service: BlockImportService<B>) -> Self {
        Self { service }
    }
}

impl<B: BlockT> Clone for SyncBlockImportAdapter<B> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

#[async_trait::async_trait]
impl<B: BlockT> BlockImport<B> for SyncBlockImportAdapter<B> {
    type Error = ConsensusError;

    async fn check_block(&self, block: BlockCheckParams<B>) -> Result<ImportResult, Self::Error> {
        self.service.check_block(block).await
    }

    async fn import_block(&self, block: BlockImportParams<B>) -> Result<ImportResult, Self::Error> {
        self.service.import_block(block).await
    }
}

#[async_trait::async_trait]
impl<B: BlockT> JustificationImport<B> for SyncBlockImportAdapter<B> {
    type Error = ConsensusError;

    async fn import_justification(
        &mut self,
        hash: B::Hash,
        number: NumberFor<B>,
        justification: Justification,
    ) -> Result<(), Self::Error> {
        self.service
            .import_justification(hash, number, justification)
            .await
    }

    async fn on_start(&mut self) -> Vec<(B::Hash, NumberFor<B>)> {
        // TODO
        Vec::new()
    }
}

// Import service

/// Sends import requests to the serial worker and awaits its responses.
#[derive(Clone)]
pub struct BlockImportService<B: BlockT> {
    to_worker: mpsc::Sender<ServiceToWorkerMsg<B>>,
}

#[async_trait::async_trait]
impl<B: BlockT> ConsensusBlockImport<B> for BlockImportService<B> {
    async fn import_proposal(&self, proposal: &Proposal<B>) -> HotstuffResult<B::Hash> {
        self.import_proposal(proposal).await
    }

    async fn import_qc(&self, qc: QC<B>) -> HotstuffResult<()> {
        self.import_qc(qc).await
    }

    async fn block_exist(&self, block_hash: B::Hash) -> HotstuffResult<()> {
        self.block_exist(block_hash).await
    }

    async fn try_commit(&self, commit_qc: &QC<B>) -> HotstuffResult<bool> {
        self.try_commit(commit_qc).await
    }
}

impl<B: BlockT> BlockImportService<B> {
    pub async fn import_proposal(&self, proposal: &Proposal<B>) -> HotstuffResult<B::Hash> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::ImportProposal(
                Box::new(proposal.clone()),
                tx,
            ))
            .await
            .ok();

        rx.await
            .map_err(|e| HotstuffError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn import_qc(&self, qc: QC<B>) -> HotstuffResult<()> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::ImportQc(Box::new(qc), tx))
            .await
            .ok();

        rx.await
            .map_err(|e| HotstuffError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn block_exist(&self, block_hash: B::Hash) -> HotstuffResult<()> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::BlockExist(block_hash, tx))
            .await
            .ok();
        rx.await
            .map_err(|_e| HotstuffError::MissingBlock(block_hash.to_string()))?
    }

    pub async fn check_block(
        &self,
        block: BlockCheckParams<B>,
    ) -> Result<ImportResult, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::CheckBlock(block, tx))
            .await
            .ok();

        rx.await
            .map_err(|e| ConsensusError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn import_block(
        &self,
        block: BlockImportParams<B>,
    ) -> Result<ImportResult, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::ImportBlock(Box::new(block), tx))
            .await
            .ok();

        rx.await
            .map_err(|e| ConsensusError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn import_justification(
        &self,
        hash: B::Hash,
        number: NumberFor<B>,
        justification: Justification,
    ) -> Result<(), ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::ImportJustification(
                hash,
                number,
                justification,
                tx,
            ))
            .await
            .ok();

        rx.await
            .map_err(|e| ConsensusError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn try_commit(&self, commit_qc: &QC<B>) -> HotstuffResult<bool> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::TryCommit(
                Box::new(commit_qc.clone()),
                tx,
            ))
            .await
            .ok();

        rx.await
            .map_err(|e| HotstuffError::ClientImport(format!("worker dropped: {e}")))?
    }

    pub async fn set_committer(&self, committer: Arc<dyn Committer<B>>) {
        self.to_worker
            .send(ServiceToWorkerMsg::SetCommitter(committer))
            .await
            .ok();
    }
}

// Import worker

/// Processes all import operations serially.
pub struct BlockImportWorker<B, BE, C, SC>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
    C::Api: BlockBuilderApi<B>,
    SC: SelectChain<B>,
{
    from_service: mpsc::Receiver<ServiceToWorkerMsg<B>>,
    inner: HotstuffBlockImporter<B, BE, C, SC>,
}

impl<B, BE, C, SC> BlockImportWorker<B, BE, C, SC>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
    C::Api: BlockBuilderApi<B>,
    SC: SelectChain<B>,
{
    pub fn new_with_service(
        inner: Arc<C>,
        select_chain: SC,
        sync_event_tx: SyncEventSender<B>,
        session_info_service: Arc<SessionInfoService<B>>,
        metrics: MetricsOpt,
    ) -> (Self, BlockImportService<B>) {
        let (to_worker, from_service) = mpsc::channel(CHANNEL_CAPACITY);
        let worker = Self {
            from_service,
            inner: HotstuffBlockImporter::new(
                inner,
                select_chain,
                sync_event_tx,
                session_info_service,
                metrics,
            ),
        };

        let service = BlockImportService { to_worker };
        (worker, service)
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.from_service.recv() => match msg {
                    ServiceToWorkerMsg::ImportProposal(proposal, sender) => {
                        let ret = self.inner.import_proposal_impl(&proposal).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::ImportQc(qc, sender) => {
                        let ret = self.inner.import_qc_impl(*qc).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::BlockExist(hash, sender) => {
                        let ret = self.inner.block_exist_impl(hash).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::CheckBlock(block, sender) => {
                        let ret = self.inner.check_block_impl(block).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::ImportBlock(block, sender) => {
                        let ret = self.inner.import_block_impl(*block).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::ImportJustification(hash, number, just, sender) => {
                        let ret = self.inner.import_justification_impl(hash, number, just).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::TryCommit(qc, sender) => {
                        let ret = self.inner.try_commit_impl(&qc).await;
                        let _ = sender.send(ret);
                    },
                    ServiceToWorkerMsg::SetCommitter(committer) => {
                        self.inner.committer = Some(committer);
                        log::debug!(target: LOG_TARGET, "Committer initialized for block importer");
                    },
                },
                else => {
                    // Channel closed, exit worker
                    log::debug!(target: LOG_TARGET, "BlockImporterWorker channel closed, exiting");
                    break;
                }
            };
        }
    }
}

// Import implementation
struct HotstuffBlockImporter<B, BE, C, SC>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
    C::Api: BlockBuilderApi<B>,
    SC: SelectChain<B>,
{
    inner: Arc<C>,
    #[allow(dead_code)]
    select_chain: SC,
    sync_event_tx: SyncEventSender<B>,
    backend: PhantomData<BE>,
    #[allow(dead_code)]
    session_info_service: Arc<SessionInfoService<B>>,
    recent_imported_cache: LruCache<B::Hash>,
    committer: Option<Arc<dyn Committer<B>>>,
    metrics: MetricsOpt,
    // memorize the block number from warp sync if it is used
    warp_sync_point: NumberFor<B>,
    _phantom: PhantomData<B>,
}

impl<B, BE, C, SC> HotstuffBlockImporter<B, BE, C, SC>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
    C::Api: BlockBuilderApi<B>,
    SC: SelectChain<B>,
{
    fn new(
        inner: Arc<C>,
        select_chain: SC,
        sync_event_tx: SyncEventSender<B>,
        session_info_service: Arc<SessionInfoService<B>>,
        metrics: MetricsOpt,
    ) -> Self {
        let warp_sync_point = match aux_store::load_warp_sync_point::<B, _>(inner.as_ref()) {
            Ok(Some(block_number)) => {
                log::info!(
                    target: LOG_TARGET,
                    "Loaded warp sync point from aux store: {}",
                    block_number,
                );
                block_number
            }
            Ok(None) => NumberFor::<B>::zero(),
            Err(err) => {
                log::error!(
                    target: LOG_TARGET,
                    "Failed to load warp sync point from aux store: {}",
                    err,
                );
                NumberFor::<B>::zero()
            }
        };

        Self {
            inner,
            select_chain,
            sync_event_tx,
            backend: PhantomData,
            session_info_service,
            recent_imported_cache: LruCache::<B::Hash>::new(RECENT_IMPORTED_LRU_SIZE),
            committer: None,
            metrics,
            warp_sync_point,
            _phantom: PhantomData,
        }
    }

    fn validate_block_number(
        &self,
        block_number: NumberFor<B>,
        block_hash: B::Hash,
        warp_sync_point: NumberFor<B>,
    ) -> HotstuffResult<()> {
        // blocks before warp sync point can be fork-synced at any time.
        if block_number < warp_sync_point {
            return Ok(());
        }
        let finalized_number = self.inner.info().finalized_number;
        if block_number <= finalized_number {
            log::warn!(
                target: LOG_TARGET,
                "Old block {:?} (number: {}) is not after finalized block (number: {}), skipping import",
                block_hash,
                block_number,
                finalized_number,
            );
            return Err(HotstuffError::ClientImport(format!(
                "Block number {} is not after finalized number {}",
                block_number, finalized_number
            )));
        }
        Ok(())
    }

    async fn verify_sync_qc(&self, qc: &QC<B>) -> Result<(), ConsensusError> {
        let authorities = self
            .session_info_service
            .authorities(qc.session_index)
            .await
            .ok_or_else(|| {
                ConsensusError::Other(
                    format!(
                        "Sync block failed, cannot to get authorities to verify QC, session: {}",
                        qc.session_index,
                    )
                    .into(),
                )
            })?;
        log::trace!(target: LOG_TARGET, "Sync block get authorities success");

        let validator_pks = authorities
            .into_iter()
            .map(|(validator_id, (_, _, bls_pk, _))| (validator_id, bls_pk))
            .collect::<Vec<_>>();

        if !sync_qc_has_quorum(qc, validator_pks.len()) {
            log::warn!(
                target: LOG_TARGET,
                "Sync block QC lacks quorum, session: {}, view: {}, participants: {}, validators: {}",
                qc.session_index,
                qc.view,
                qc.agg_sig.participants().len(),
                validator_pks.len(),
            );
            return Err(ConsensusError::InvalidJustification);
        }

        if !verify_qc_with_validator_pks(qc, &validator_pks) {
            return Err(ConsensusError::InvalidJustification);
        }

        log::trace!(target: LOG_TARGET, "Sync block verify qc success");
        Ok(())
    }

    /// Record an authority-set change-point if `digest` carries a `NextAuthoritySet`. Called from
    /// both import paths (sync and consensus) so nodes serving warp proofs build a complete index
    /// regardless of how they imported the block. Best-effort: persistence only, never fails import.
    fn record_change_point_best_effort(
        &self,
        digest: &Digest,
        number: NumberFor<B>,
        hash: B::Hash,
    ) {
        if let Err(err) =
            aux_store::maybe_record_change_point::<B, _>(self.inner.as_ref(), digest, number, hash)
        {
            log::error!(
                target: LOG_TARGET,
                "failed to record warp change-point at #{number} ({hash:?}): {err}",
            );
        }
    }

    async fn import_proposal_impl(&mut self, proposal: &Proposal<B>) -> HotstuffResult<B::Hash> {
        // Write proposer validatorId to block digest log
        // Use PreRuntime instead of Consensus to ensure it's sealed in the block header
        // before on_finalize adds other Consensus digests
        let digest_item = DigestItem::PreRuntime(
            HOTSTUFF_CONSENSUS_ID,
            ConsensusLog::Proposer(proposal.leader_id.clone()).encode(),
        );
        let digest = Digest {
            logs: vec![digest_item],
        };
        // make a block by using sp_block_builder
        let mut block_builder = BlockBuilderBuilder::<B, C>::new(&*self.inner)
            .on_parent_block(*proposal.parent_hash())
            .with_parent_block_number(*proposal.parent_number())
            // .fetch_parent_block_number(&*self.inner)
            // .expect("fetch parent number")
            .with_inherent_digests(digest)
            .build()
            .expect("create block builder");

        let txs = opaque_exts_2_exts::<B>(proposal.extrinsics());

        let push_start = std::time::Instant::now();
        for (idx, tx) in txs.into_iter().enumerate() {
            // TODO remove clone()
            match block_builder.push(tx.clone()) {
                Ok(_) => {}
                Err(ClientError::ApplyExtrinsicFailed(ApplyExtrinsicFailed::Validity(
                    TransactionValidityError::Invalid(InvalidTransaction::ExhaustsResources),
                ))) => {
                    log::warn!(
                        target: LOG_TARGET,
                        "extrinsic {:?} failed: exhausted resources",
                        hash_of::<B>(&tx.encode())
                    );
                    break;
                }
                Err(ClientError::ApplyExtrinsicFailed(ApplyExtrinsicFailed::Validity(e))) => {
                    log::warn!(
                        target: LOG_TARGET,
                        "extrinsic {:?} skipped: invalid extrinsics, {e}",
                        hash_of::<B>(&tx.encode())
                    );
                    continue;
                }
                Err(e) => {
                    return Err(HotstuffError::BlockBuild(format!(
                        "proposal invalid: extrinsic #{idx} failed to apply: {e}"
                    )));
                }
            }
        }
        let push_elapsed = push_start.elapsed();
        let total_items = proposal.extrinsics().len();
        if total_items > 0 {
            let per_item = push_elapsed / total_items as u32;
            log::trace!(
                target: LOG_TARGET,
                "block_builder.push, view: {}, took {:?} for {} items (avg {:?} per item)",
                proposal.view,
                push_elapsed,
                total_items,
                per_item
            );
            self.metrics
                .set_block_builder_push_avg_time_us(per_item.as_micros() as u64);
        }

        let built = block_builder
            .build()
            .map_err(|e| HotstuffError::BlockBuild(e.to_string()))?;
        let block = built.block;

        // don't make notifications while importing
        // BlockOrigin::NetworkBroadcast|Own|ConsensusBroadcast will notify
        let mut params = BlockImportParams::<B>::new(BlockOrigin::File, block.header().clone());
        params.body = Some(block.extrinsics().to_vec());
        params.state_action =
            StateAction::ApplyChanges(ImportStorageChanges::Changes(built.storage_changes));
        params.fork_choice = Some(ForkChoiceStrategy::Custom(false));

        log::trace!(
            target: LOG_TARGET,
            "[import_proposal] view: {}, block_hash: {:?}, digest: {:?}",
            proposal.view,
            block.hash(),
            block.header().digest(),
        );

        // Validate block number is after finalized number
        if let Err(_e) =
            self.validate_block_number(*block.header().number(), block.hash(), self.warp_sync_point)
        {
            return Ok(block.hash());
        }

        match self.inner.import_block(params).await {
            Ok(ImportResult::Imported(_aux)) => {
                // Validators import via this consensus path, not the sync path, so record here too.
                self.record_change_point_best_effort(
                    block.header().digest(),
                    *block.header().number(),
                    block.hash(),
                );
                Ok(block.hash())
            }
            Ok(ImportResult::AlreadyInChain) => Ok(block.hash()),
            Ok(_) => Err(HotstuffError::ClientImport(format!(
                "import block failed: {}",
                block.hash()
            ))),
            Err(e) => Err(HotstuffError::ClientImport(e.to_string())),
        }
    }

    async fn import_qc_impl(&mut self, qc: QC<B>) -> HotstuffResult<()> {
        if qc.is_genesis(&self.inner.info().genesis_hash) {
            return Ok(());
        }
        let block_hash = qc.block_hash;

        let header = self
            .inner
            .header(block_hash)
            .map_err(|e| HotstuffError::ClientImport(e.to_string()))?
            .ok_or_else(|| {
                HotstuffError::ClientImport(format!("missing header: {:?}", block_hash))
            })?;

        // A old QC will not change the best
        let client_info = self.inner.info();
        let should_change_best =
            client_info.best_hash == block_hash || client_info.best_number < *header.number();

        log::trace!(
            target: LOG_TARGET,
            "[import_qc] block_hash: {:?}, block_number: {}, current_best_hash: {:?}, current_best_number: {}, change_best: {}",
            block_hash,
            *header.number(),
            client_info.best_hash,
            client_info.best_number,
            should_change_best,
        );

        // Validate block number is after finalized number
        if let Err(_e) =
            self.validate_block_number(*header.number(), block_hash, self.warp_sync_point)
        {
            return Ok(());
        }

        // make notifications
        let mut params = BlockImportParams::<B>::new(BlockOrigin::ConsensusBroadcast, header);
        params.import_existing = true;
        params.state_action = StateAction::Skip;
        params.body = None;
        params.justifications = Some(Justifications::from(qc.into_justification()));
        params.finalized = false;
        // Old QCs should still be imported as justifications, but they must not move best backward
        // and trigger unnecessary reorgs.
        params.fork_choice = Some(ForkChoiceStrategy::Custom(should_change_best));

        match self.inner.import_block(params).await {
            Ok(ImportResult::Imported(_)) | Ok(ImportResult::AlreadyInChain) => {
                self.recent_imported_cache.insert(block_hash);
                Ok(())
            }
            Ok(other) => Err(HotstuffError::ClientImport(format!(
                "unexpected import result: {other:?}"
            ))),
            Err(e) => Err(HotstuffError::ClientImport(e.to_string())),
        }
    }

    async fn block_exist_impl(&self, block_hash: B::Hash) -> HotstuffResult<()> {
        if self.recent_imported_cache.contains(&block_hash) {
            return Ok(());
        }

        match self.inner.status(block_hash) {
            Ok(block_status) => {
                if BlockStatus::Unknown == block_status {
                    Err(HotstuffError::MissingBlock(
                        format!("hash: {}", block_hash,),
                    ))
                } else {
                    Ok(())
                }
            }
            Err(e) => return Err(HotstuffError::MissingBlock(e.to_string())),
        }
    }

    async fn check_block_impl(
        &self,
        block: BlockCheckParams<B>,
    ) -> Result<ImportResult, ConsensusError> {
        if self.recent_imported_cache.contains(&block.hash) {
            return Ok(ImportResult::AlreadyInChain);
        }

        log::trace!(target: LOG_TARGET, "check_block hash: {:?} number: {}", block.hash, block.number);
        self.inner
            .check_block(block)
            .await
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))
    }

    // Block syncing not required the parent block is the best(has a QC),
    // so reorgs can happen if a QC for an old block comes after a synced block, which are ok.
    // Example logs:
    //  🏃 SyncFinalize by qc, qc.view: 6473722, qc.block_hash: 0x4988…6cae, qc.block_number: 5661921
    //  🏆 Imported #5661921 (0xb070…a63d → 0x4988…6cae)
    //  ♻️  Reorg on #5661921,0x4988…6cae to #5661920,0xb070…a63d, common ancestor #5661920,0xb070…a63d
    //  🏆 Imported #5661920 (0x04a4…0b15 → 0xb070…a63d)
    async fn import_block_impl(
        &mut self,
        mut block: BlockImportParams<B>,
    ) -> Result<ImportResult, ConsensusError> {
        let is_from_warp_sync = matches!(
            block.state_action,
            StateAction::ApplyChanges(ImportStorageChanges::Import(_))
        );
        if is_from_warp_sync {
            // Finalize the warp target during import. Upstream `apply_block` marks a `finalized`
            // block as Final without recursing into its (absent) parent because `parent_exists`
            // is false — so no custom non-recursive finalizer is needed.
            block.finalized = true;
        }
        let block_hash = block.post_hash();
        let block_number = *block.header.number();
        log::trace!(
            target: LOG_TARGET,
            "import_block has_qc: {:?} hash: {:?}, origin: {:?}, fork_choice: {:?}, from_warp: {}",
            block.justifications.is_some(),
            block_hash,
            block.origin,
            block.fork_choice,
            is_from_warp_sync,
        );

        // For block syncing, the importing number is not required to be bigger than latest
        // finalized number, eg. Warp sync scenarios
        if let Err(_e) = self.validate_block_number(block_number, block_hash, self.warp_sync_point)
        {
            return Ok(ImportResult::AlreadyInChain);
        }

        // for handle_new_view process
        let qc = match block.justifications.as_ref() {
            Some(justs) => {
                let Some(qc) = QC::<B>::from_justifications(justs.clone()) else {
                    log::error!(
                        target: LOG_TARGET,
                        "Failed to decode qc from justifications for block",
                    );
                    return Err(ConsensusError::InvalidJustification);
                };
                // Verify qc for every non-warp-synced block, including historical (back-fill)
                // blocks below the warp sync point: their authorities are now resolved from the
                // persisted warp authority map (see SessionInfoService historical resolution), so
                // QC verification no longer requires historical chain state. The warp-synced target
                // block itself is verified inside warp-proof verification.
                if !is_from_warp_sync {
                    self.verify_sync_qc(&qc).await?;
                }

                Some(qc)
            }
            None => {
                log::trace!(
                    target: LOG_TARGET,
                    "synced block has no qc, hash: {:?}",
                    block_hash,
                );
                None
            }
        };

        // Capture the digest before `block` is moved into `import_block` below.
        let header_digest_for_record = block.header.digest().clone();

        let import_result = self.inner.import_block(block).await;
        let imported_aux = {
            match import_result {
                Ok(ImportResult::Imported(aux)) => {
                    log::trace!(
                        target: LOG_TARGET,
                        "[success] imported best by syncing",
                    );

                    self.record_change_point_best_effort(
                        &header_digest_for_record,
                        block_number,
                        block_hash,
                    );

                    if !is_from_warp_sync {
                        if let Some(qc) = qc {
                            let event = if self.warp_sync_point > block_number {
                                SyncEvent::OnHistoricalQC(Box::new(qc))
                            } else {
                                SyncEvent::OnQC(Box::new(qc))
                            };
                            let _ = self.sync_event_tx.try_send(event);
                        }
                    } else {
                        // Warp target: already finalized during import (block.finalized = true).
                        // The SyncEngine starts earlier than the committer/sync-event-handler, so
                        // finalization happens inline via the stock import path, not a worker.
                        log::info!(
                            target: LOG_TARGET,
                            "✅ Warp Finalized {:?}",
                            block_hash,
                        );
                        self.warp_sync_point = block_number;
                        if let Err(err) = aux_store::save_warp_sync_point::<B, _>(
                            self.inner.as_ref(),
                            block_number,
                        ) {
                            log::error!(
                                target: LOG_TARGET,
                                "Failed to persist warp sync point {}: {}",
                                block_number,
                                err,
                            );
                        }
                        self.session_info_service.advance_current_session().await;
                    }

                    aux
                }
                Ok(r) => {
                    log::trace!(
                        target: LOG_TARGET,
                        "import message: {:?}", r,
                    );
                    return Ok(r);
                }
                Err(e) => {
                    return {
                        log::error!(
                            target: LOG_TARGET,
                            "Failed to import block by syncing, err: {}",
                            e,
                        );
                        Err(ConsensusError::ClientImport(e.to_string()))
                    }
                }
            }
        };

        Ok(ImportResult::Imported(imported_aux))
    }

    async fn import_justification_impl(
        &mut self,
        hash: B::Hash,
        _number: NumberFor<B>,
        justification: Justification,
    ) -> Result<(), ConsensusError> {
        let justs = Justifications::from(justification);
        let Some(qc) = QC::<B>::from_justifications(justs.clone()) else {
            log::error!(target: LOG_TARGET, "Failed to decode qc from justifications for block: {hash:?}");
            return Err(ConsensusError::InvalidJustification);
        };

        self.verify_sync_qc(&qc).await?;

        let header = self
            .inner
            .header(hash)
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            .ok_or_else(|| ConsensusError::ClientImport(format!("missing header: {hash:?}")))?;

        // accept the qc only when parent block is the best
        if self.inner.info().best_hash != *header.parent_hash() {
            log::trace!(
                target: LOG_TARGET,
                "sync justification failed, parent_hash: {} it not the best, cur best: {}",
                *header.parent_hash(),
                self.inner.info().best_hash,
            );
            return Err(ConsensusError::ClientImport(
                "parent block is not the best".to_string(),
            ));
        }

        log::trace!(
            target: LOG_TARGET,
            "sync justification success, qc: {}, block: {}",
            qc.view,
            qc.block_hash,
        );

        // from syncing, no notification broadcasted
        let mut params = BlockImportParams::<B>::new(BlockOrigin::NetworkInitialSync, header);
        params.import_existing = true;
        params.state_action = StateAction::Skip;
        params.body = None;
        params.justifications = Some(justs);
        params.finalized = false;
        // will notify all validators from best block to current block
        params.fork_choice = Some(ForkChoiceStrategy::Custom(true));

        match self.import_block_impl(params).await {
            Ok(ImportResult::Imported(_)) | Ok(ImportResult::AlreadyInChain) => {
                // send event to Core, the consensus layer will update the state based on qc
                let _ = self.sync_event_tx.try_send(SyncEvent::OnQC(Box::new(qc)));
                Ok(())
            }
            Ok(other) => Err(ConsensusError::ClientImport(format!(
                "unexpected import result: {other:?}"
            ))),
            Err(e) => Err(ConsensusError::ClientImport(e.to_string())),
        }
    }

    async fn try_commit_impl(&self, commit_qc: &QC<B>) -> HotstuffResult<bool> {
        // If committer is not set, skip commit (no finalization capability)
        let Some(committer) = &self.committer else {
            log::trace!(
                target: LOG_TARGET,
                "Committer not initialized, skipping commit for QC view: {}",
                commit_qc.view
            );
            return Ok(false);
        };

        log::trace!(
            target: LOG_TARGET,
            "try_commit qc view: {}, block: {:?}",
            commit_qc.view,
            commit_qc.block_hash,
        );

        // Phase 1: Check if we should commit (first time check)
        let Some(commit_info) = committer.should_commit(commit_qc).await? else {
            // Already processed or should skip
            return Ok(false);
        };

        // Phase 2: Finalize the block through client
        self.commit_block(commit_info.block_hash, commit_info.block_number)
            .await?;

        // Phase 3: Mark as committed (update cache and state) only after successful finalization
        committer
            .mark_committed(
                commit_info.qc_hash,
                commit_info.block_hash,
                commit_info.block_number,
            )
            .await;

        Ok(true)
    }

    async fn commit_block(
        &self,
        commit_hash: B::Hash,
        _commit_number: NumberFor<B>,
    ) -> HotstuffResult<()> {
        let res = self.inner.finalize_block(commit_hash, None, true);
        match res {
            Ok(()) => {
                log::info!(
                    target: LOG_TARGET,
                    "✅ Finalized {:?}",
                    commit_hash,
                );
            }
            Err(err) => {
                log::info!(
                    target: LOG_TARGET,
                    "💔 Error Finalize {:?} {:?}",
                    commit_hash, err,
                );
                return Err(HotstuffError::ClientImport(err.to_string()));
            }
        }
        Ok(())
    }
}

fn sync_qc_has_quorum<B: BlockT>(qc: &QC<B>, total_validators: usize) -> bool {
    if total_validators == 0 {
        return false;
    }

    let quorum = quorum_voting_power_from_total(total_validators);
    qc.agg_sig.participants().len() >= quorum
}

// Sync verifier and import queue

#[derive(Clone)]
pub struct HotstuffVerifier<B: BlockT> {
    _phantom: PhantomData<B>,
}

impl<B: BlockT> HotstuffVerifier<B> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<B: BlockT> Default for HotstuffVerifier<B> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl<B: BlockT> Verifier<B> for HotstuffVerifier<B> {
    async fn verify(
        &self,
        mut params: BlockImportParams<B>,
    ) -> Result<BlockImportParams<B>, String> {
        // for syncing, origin should be NetworkInitialSync
        params.fork_choice = Some(ForkChoiceStrategy::Custom(params.justifications.is_some()));

        log::trace!(
            target: LOG_TARGET,
            "import_queue verifying block: {}, with_qc: {}",
            params.post_hash(),
            params.justifications.is_some(),
        );

        Ok(params)
    }
}

pub fn import_queue<B, S>(
    block_import: BoxBlockImport<B>,
    justification_import: Option<BoxJustificationImport<B>>,
    spawner: &S, // &sc_service::TaskManager
    registry: Option<&Registry>,
) -> Result<DefaultImportQueue<B>, sp_consensus::Error>
where
    B: BlockT,
    S: sp_core::traits::SpawnEssentialNamed,
{
    let verifier = build_verifier();
    Ok(DefaultImportQueue::new(
        verifier,
        block_import,
        justification_import,
        spawner,
        registry,
    ))
}

fn build_verifier<B: BlockT>() -> HotstuffVerifier<B> {
    HotstuffVerifier::<B>::new()
}

pub fn block_import<BE, B: BlockT, C, SC>(
    client: Arc<C>,
    select_chain: SC,
    session_info_service: Arc<SessionInfoService<B>>,
    metrics: MetricsOpt,
) -> Result<
    (
        BlockImportWorker<B, BE, C, SC>,
        BlockImportService<B>,
        SyncEventReceiver<B>,
    ),
    ClientError,
>
where
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: BlockBuilderApi<B>,
    SC: SelectChain<B> + 'static,
{
    let (sync_event_tx, sync_event_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (worker, service) = BlockImportWorker::new_with_service(
        client,
        select_chain,
        sync_event_tx,
        session_info_service,
        metrics,
    );
    Ok((worker, service, sync_event_rx))
}

// Block finalization

// Information about a block ready to commit
pub struct CommitInfo<B: BlockT> {
    pub block_hash: B::Hash,
    pub block_number: NumberFor<B>,
    pub qc_hash: B::Hash,
}

// Committer trait for block finalization
#[async_trait::async_trait]
pub trait Committer<B: BlockT>: Send + Sync {
    /// Check if a block should be committed based on the commit QC
    /// Returns Some(CommitInfo) if this is a new commit (first time), None if already processed or should skip
    async fn should_commit(&self, commit_qc: &QC<B>) -> HotstuffResult<Option<CommitInfo<B>>>;

    /// Mark a commit as completed after successful finalization
    async fn mark_committed(
        &self,
        qc_hash: B::Hash,
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    );
}

// Default implementation that wraps StateService
pub struct HotstuffCommitter<B: BlockT> {
    state_service: StateService<B>,
    client: Arc<dyn sp_blockchain::HeaderBackend<B> + Send + Sync>,
    recent_finalized_cache: Arc<parking_lot::Mutex<LruCache<B::Hash>>>,
}

impl<B: BlockT> HotstuffCommitter<B> {
    pub fn new(
        state_service: StateService<B>,
        client: Arc<dyn sp_blockchain::HeaderBackend<B> + Send + Sync>,
    ) -> Self {
        Self {
            state_service,
            client,
            recent_finalized_cache: Arc::new(parking_lot::Mutex::new(LruCache::new(
                RECENT_FINALIZED_LRU_SIZE,
            ))),
        }
    }
}

#[async_trait::async_trait]
impl<B: BlockT> Committer<B> for HotstuffCommitter<B> {
    async fn should_commit(&self, commit_qc: &QC<B>) -> HotstuffResult<Option<CommitInfo<B>>> {
        let commit_qc_hash = commit_qc.hash();

        // Check if this QC has already been processed
        if self.recent_finalized_cache.lock().contains(&commit_qc_hash) {
            log::trace!(
                target: LOG_TARGET,
                "Commit QC for block {:?} already processed, skipping",
                commit_qc_hash
            );
            return Ok(None);
        }

        // Get locked block header
        let locked_header = match self.client.header(commit_qc.block_hash) {
            Ok(Some(header)) => header,
            Ok(None) => {
                log::warn!(
                    target: LOG_TARGET,
                    "Parent block {:?} not found for commit QC",
                    commit_qc.block_hash
                );
                return Err(HotstuffError::MissingBlock(format!(
                    "hash: {:?}",
                    commit_qc.block_hash
                )));
            }
            Err(e) => {
                log::error!(
                    target: LOG_TARGET,
                    "Failed to get parent block header {:?}: {}",
                    commit_qc.block_hash,
                    e
                );
                return Err(HotstuffError::ClientImport(e.to_string()));
            }
        };

        log::trace!(
            target: LOG_TARGET,
            "locked block: {:?}, number: {}",
            locked_header.hash(),
            locked_header.number()
        );

        let commit_hash = locked_header.parent_hash();
        // Get parent QC from state service
        let locked_qc = if let Some(qc) = self.state_service.get_qc_of_block(&commit_hash).await {
            qc
        } else {
            log::trace!(
                target: LOG_TARGET,
                "Locked QC not found for block {:?}",
                commit_hash
            );
            return Ok(None);
        };

        log::trace!(
            target: LOG_TARGET,
            "locked qc view: {}, block: {:?}, number: {}",
            locked_qc.view,
            locked_qc.block_hash,
            locked_qc.block_number,
        );

        // Validate parent QC block number is after finalized number
        let commit_number = locked_qc.block_number;
        let finalized_number = self.client.info().finalized_number;
        if commit_number <= finalized_number {
            log::debug!(
                target: LOG_TARGET,
                "😛 Invalid Finalize, block number: {} <= latest_finalized_number: {}",
                commit_number,
                finalized_number
            );
            return Ok(None);
        }

        log::trace!(
            target: LOG_TARGET,
            "Should commit: (hash: {}, number: {}) <- (locked_qc: {}, qc.number: {}) <- (commit_qc: {}, qc.number: {})",
            commit_hash,
            commit_number,
            locked_qc.view,
            locked_qc.block_number,
            commit_qc.view,
            commit_qc.block_number,
        );

        Ok(Some(CommitInfo {
            block_hash: *commit_hash,
            block_number: commit_number,
            qc_hash: commit_qc_hash,
        }))
    }

    async fn mark_committed(
        &self,
        qc_hash: B::Hash,
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    ) {
        // Update finalized cache
        self.recent_finalized_cache.lock().insert(qc_hash);

        // Update leader election state
        self.state_service
            .update_leader_election_state(block_hash, block_number)
            .await;

        log::trace!(
            target: LOG_TARGET,
            "Commit marked: block_hash: {:?}, block_number: {}, qc_hash: {:?}",
            block_hash,
            block_number,
            qc_hash,
        );
    }
}

#[cfg(test)]
#[path = "../unit_tests/block_importer.rs"]
mod tests;
