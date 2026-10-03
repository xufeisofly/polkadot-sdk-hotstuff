use crate::{
    crypto::{AggregateSignature, Crypto},
    error::{HotstuffError, HotstuffResult},
    measure_time,
    messages::{
        ConsensusMessage, ConsensusOp, NewView, NewViewParams, Proposal, ProposeParams, SyncInfo,
    },
    metrics::MetricsOpt,
    network::{HotstuffNetworkSender, Network},
    primitives::{exts_2_opaque_exts, ValidatorId, ViewNumber, MAX_PROPOSAL_TX_BYTES},
    session_info_provider::{SessionAuthorityProvider, SessionInfoService},
};
use codec::Encode;
use sc_client_api::Backend;
use sc_service::InPoolTransaction;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::Backend as ChainBackend;
use sp_blockchain::HeaderBackend;
use sp_consensus_hotstuff::SessionIndex;
use sp_core::hexdisplay::AsBytesRef;
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::{
    traits::{Block as BlockT, Header, NumberFor, Saturating},
    OpaqueExtrinsic,
};
use std::{marker::PhantomData, sync::Arc};
use tokio::sync::mpsc::Receiver;

const LOG_TARGET: &str = "sc-consensus-hotstuff::proposer";

#[derive(Clone)]
struct CachedProposalTxs<B: BlockT> {
    parent_hash: B::Hash,
    block_number: NumberFor<B>,
    opaque_txs: Vec<OpaqueExtrinsic>,
}

pub struct Proposer<B, BE, C, P, CR, N, CIDP>
where
    B: BlockT,
    BE: Backend<B>,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
    C::Api: BlockBuilderApi<B>,
    P: TransactionPool<Block = B> + 'static,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    N: Network<B> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
{
    create_inherent_data_providers: CIDP,
    client: Arc<C>,
    backend: Arc<BE>,
    pool: Arc<P>,
    network: HotstuffNetworkSender<B, N>,
    crypto: CR,
    max_txs: usize,
    session_info_service: Arc<SessionInfoService<B>>,
    metrics: MetricsOpt,

    op_rx: Receiver<ConsensusOp<B>>,
    last_proposal_txs: Option<CachedProposalTxs<B>>,
    _phantom: PhantomData<BE>,
}

impl<B, BE, C, P, CR, N, CIDP> Proposer<B, BE, C, P, CR, N, CIDP>
where
    B: BlockT,
    BE: Backend<B>,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
    C::Api: BlockBuilderApi<B>,
    P: TransactionPool<Block = B> + 'static,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    N: Network<B> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
{
    pub fn new(
        create_inherent_data_providers: CIDP,
        client: Arc<C>,
        _backend: Arc<BE>,
        pool: Arc<P>,
        network: HotstuffNetworkSender<B, N>,
        crypto: CR,
        max_txs: usize,
        session_info_service: Arc<SessionInfoService<B>>,
        metrics: MetricsOpt,
        op_rx: Receiver<ConsensusOp<B>>,
    ) -> Self {
        Self {
            create_inherent_data_providers,
            client,
            backend: _backend,
            pool,
            network,
            crypto,
            max_txs,
            session_info_service,
            metrics,
            op_rx,
            last_proposal_txs: None,
            _phantom: PhantomData,
        }
    }

    pub async fn propose(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        leader_id: ValidatorId,
        validator_ids_hash: B::Hash,
        sync_info: SyncInfo<B>,
        force: bool,
    ) {
        log::trace!(target: LOG_TARGET, "Enter propose, view: {}-{}", session_index, view);
        let start = std::time::Instant::now();

        match self
            .generate_proposal(
                view,
                session_index,
                leader_id.clone(),
                validator_ids_hash,
                sync_info.clone(),
                force,
            )
            .await
        {
            Ok(proposal) => {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                self.metrics.set_proposal_construction_time_ms(elapsed_ms);

                log::trace!(
                    target: LOG_TARGET,
                    "Propose: for view {}-{} in {}ms, txs: {}",
                    session_index,
                    view,
                    elapsed_ms,
                    proposal.payload.extrinsics.len(),
                );

                self.network
                    .broadcast_message(ConsensusMessage::Proposal(proposal));
                // TODO local handle proposal
            }
            Err(e) => {
                match &e {
                    HotstuffError::NoTx => log::info!(
                        target: LOG_TARGET,
                        "Failed to generate proposal for view {}-{}: {}, send new_view instead",
                        session_index,
                        view,
                        e
                    ),
                    _ => log::warn!(
                        target: LOG_TARGET,
                        "Failed to generate proposal for view {}-{}: {}, send new_view instead",
                        session_index,
                        view,
                        e
                    ),
                }
                self.new_view(view, session_index, leader_id, sync_info)
                    .await;
            }
        }
    }

    pub async fn new_view(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        _leader_id: ValidatorId,
        sync_info: SyncInfo<B>,
    ) {
        log::trace!(target: LOG_TARGET, "Enter newview, view: {}-{}", session_index, view);

        let new_view = NewView::new(
            view,
            session_index,
            sync_info.qc,
            sync_info.tc,
            sync_info.agg_qc,
        );
        self.network
            .broadcast_message(ConsensusMessage::NewView(new_view));
    }

    async fn select_transactions(
        &mut self,
        parent_hash: B::Hash,
        block_number: NumberFor<B>,
        _force: bool,
    ) -> HotstuffResult<Vec<Arc<B::Extrinsic>>> {
        let status = self.pool.status();
        log::debug!(
            target: LOG_TARGET,
            "TxPool State: ready = {}, future = {}",
            status.ready,
            status.future,
        );
        self.metrics
            .set_txpool_status(status.ready as u64, status.future as u64);

        match self.client.status(parent_hash) {
            Ok(block_status) => {
                log::trace!(target: LOG_TARGET, "parent_block status: {:?}", block_status);
            }
            Err(e) => {
                log::error!(target: LOG_TARGET, "parent_block status failed, {e:?}");
            }
        }

        let providers = self
            .create_inherent_data_providers
            .create_inherent_data_providers(parent_hash, ())
            .await
            .map_err(|e| HotstuffError::BlockBuild(e.to_string()))?;
        let data = providers
            .create_inherent_data()
            .await
            .map_err(|e| HotstuffError::BlockBuild(e.to_string()))?;
        let inherents: Vec<_> = self
            .client
            .runtime_api()
            .inherent_extrinsics(parent_hash, data)
            .map_err(|e| HotstuffError::BlockBuild(e.to_string()))?
            .into_iter()
            .map(Arc::new)
            .collect();
        let inherents_num = inherents.len();

        // Check if this is a session rotation block
        let should_end = self
            .session_info_service
            .should_end_session(block_number)
            .await;
        if should_end {
            log::info!(
                target: LOG_TARGET,
                "Block #{} is session rotation block, only including inherents (no txpool transactions)",
                block_number,
            );
            return Ok(inherents);
        }

        // TODO other inherents
        // let inherents = self.client
        //     .runtime_api()
        //     .inherent_extrinsics(parent_hash, inherent_data)?;

        let mut transactions = inherents;
        let mut selected_bytes = transactions
            .iter()
            .map(|tx| tx.encoded_size())
            .sum::<usize>();
        if self.pool.status().ready != 0 {
            let client_info = self.client.info();
            if client_info.best_hash == parent_hash {
                let ready_iter =
                    measure_time!("ready_at", { self.pool.ready_at(parent_hash).await });
                for tx in ready_iter {
                    let xt = tx.data().clone();
                    if transactions.len() >= self.max_txs {
                        log::trace!(
                            target: LOG_TARGET,
                            "select transactions, reached max transaction limit: {}", self.max_txs,
                        );
                        break;
                    }

                    let xt_bytes = xt.encoded_size();
                    if !transactions.is_empty()
                        && selected_bytes.saturating_add(xt_bytes) > MAX_PROPOSAL_TX_BYTES
                    {
                        log::info!(
                            target: LOG_TARGET,
                            "select transactions, reached proposal byte limit: current_bytes={}, next_tx_bytes={}, limit={}",
                            selected_bytes,
                            xt_bytes,
                            MAX_PROPOSAL_TX_BYTES,
                        );
                        break;
                    }

                    selected_bytes = selected_bytes.saturating_add(xt_bytes);
                    transactions.push(xt);
                }
            } else {
                log::warn!(
                    target: LOG_TARGET,
                    "parent_hash {} is not the best, the best: {}",
                    parent_hash,
                    self.client.info().best_hash,
                )
            }
        }

        if transactions.is_empty() {
            Err(HotstuffError::NoTx)
        } else if transactions.len() <= inherents_num {
            {
                // Generally, A normal block can have 2 empty blocks afterwards to ensure finalization
                // if !force && self.extrinsics_count(parent_hash) <= inherents_num {
                if !_force {
                    return Err(HotstuffError::NoTx);
                } else {
                    // An extra empty proposal is required to finalize its parent
                    return Ok(transactions);
                }
            }
        } else {
            Ok(transactions)
        }
    }

    #[allow(dead_code)]
    fn extrinsics_count(&self, hash: B::Hash) -> usize {
        if let Ok(Some(extrinsics)) = self.backend.blockchain().body(hash) {
            let count = extrinsics.iter().count();
            log::trace!("Block {} has {} non-inherent transactions", hash, count);
            count
        } else {
            0
        }
    }

    async fn generate_proposal(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        leader_id: ValidatorId,
        validator_ids_hash: B::Hash,
        sync_info: SyncInfo<B>,
        force: bool,
    ) -> HotstuffResult<Proposal<B>> {
        // qc and view are the high_qc and cur_view from Core
        let qc = sync_info.qc.ok_or(HotstuffError::InvalidParams)?;

        // happy path propose
        let parent_hash = qc.block_hash;
        let parent_header = match self.client.header(parent_hash) {
            Ok(Some(header)) => header,
            Ok(None) => {
                // self.sync
                //     .set_sync_fork_request(vec![], parent_hash, qc.block_number);
                return Err(HotstuffError::MissingBlock(parent_hash.to_string()));
            }
            Err(e) => {
                // self.sync
                //     .set_sync_fork_request(vec![], parent_hash, qc.block_number);
                return Err(HotstuffError::MissingBlock(e.to_string()));
            }
        };

        let parent_number = *parent_header.number();
        let block_number: NumberFor<B> = parent_number.saturating_plus_one();
        let opaque_txs = self
            .get_or_create_proposal_txs(parent_hash, block_number, force)
            .await?;

        let mut proposal = Proposal::new(
            qc,
            sync_info.tc, // tc and agg_qc can be None
            sync_info.agg_qc,
            view,
            session_index,
            leader_id,
            validator_ids_hash,
            block_number,
            opaque_txs,
        );

        // sign with leader authority
        let leader_sig = self
            .crypto
            .authority_sign(proposal.core.encode().as_bytes_ref(), session_index)
            .await
            .map_err(|e| HotstuffError::SignFailed(e.to_string()))?;
        proposal.set_leader_sig(leader_sig);

        Ok(proposal)
    }

    async fn get_or_create_proposal_txs(
        &mut self,
        parent_hash: B::Hash,
        block_number: NumberFor<B>,
        force: bool,
    ) -> HotstuffResult<Vec<OpaqueExtrinsic>> {
        if let Some(cached) = self.last_proposal_txs.as_ref() {
            if cached.parent_hash == parent_hash && cached.block_number == block_number {
                log::debug!(
                    target: LOG_TARGET,
                    "Reuse cached proposal txs for parent {} at block #{}",
                    parent_hash,
                    block_number,
                );
                return Ok(cached.opaque_txs.clone());
            }
        }

        let transactions = self
            .select_transactions(parent_hash, block_number, force)
            .await?;

        log::trace!(
            target: LOG_TARGET,
            "selected txs: {:?}",
            transactions.iter().map(|tx| self.pool.hash_of(tx)).collect::<Vec<_>>(),
        );

        let opaque_txs = exts_2_opaque_exts::<B>(transactions);
        self.last_proposal_txs = Some(CachedProposalTxs {
            parent_hash,
            block_number,
            opaque_txs: opaque_txs.clone(),
        });

        Ok(opaque_txs)
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(message) = self.op_rx.recv() => match message {
                    ConsensusOp::<B>::Propose(ProposeParams{view, session_index, leader_id, validator_ids_hash, sync_info, force_propose}) => {
                        self.propose(view, session_index, leader_id, validator_ids_hash, sync_info, force_propose).await;
                    },
                    ConsensusOp::<B>::NewView(NewViewParams{view, session_index, leader_id, sync_info}) => {
                        self.new_view(view, session_index, leader_id, sync_info).await;
                    },
                    _ => {},
                },
                else => {
                    log::info!(target: LOG_TARGET, "Proposer op_rx closed, exiting proposer loop");
                    break;
                }
            }
        }
    }
}
