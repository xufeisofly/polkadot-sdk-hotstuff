use std::{collections::HashSet, marker::PhantomData, net::IpAddr, sync::Arc};

use sc_client_api::Backend;
use sc_network::{multiaddr::Protocol as MultiaddrProtocol, Multiaddr};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_consensus_hotstuff::HotstuffApi;
use sp_consensus_hotstuff::SessionIndex;

use sp_authority_discovery::AuthorityDiscoveryApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use tokio::sync::{
    mpsc::{Receiver, Sender, UnboundedReceiver},
    oneshot,
};

use crate::{
    aggregator::HighQcAggregator,
    block_importer::ConsensusBlockImport,
    block_syncer::BlockSyncerService,
    chain_status::{ChainStatusNotification, ChainStatusNotifier},
    client::HotstuffClient,
    crypto::{AggregateSignature, Crypto, Participants, QuorumSignature},
    error::{CryptoError, HotstuffError, HotstuffResult},
    leader_validator::{LeaderElectionContextBuilder, LeaderValidator},
    measure_time,
    messages::{
        high_qc_in_timeout_payload_hash, timeout_tc_payload_hash, vote_qc_payload_hash, AggQC,
        ConsensusMessage, ConsensusOp, NewView, NewViewParams, Proposal, ProposeParams, SyncInfo,
        Timeout, TimeoutParams, Vote, QC, TC,
    },
    metrics::MetricsOpt,
    network::{HotstuffNetworkSender, Network, PeerLifecycleEvent},
    peer_provider::PeerProviderService,
    primitives::{
        extended_from, ValidatorId, ViewNumber, GENESIS_VIEW, PEER_WAIT_INTERVAL,
        REFRESH_RESERVED_PEERS_INTERVAL_SECS, VIEW_DUR_MAX_TIMEOUT_MS, VIEW_DUR_MIN_TIMEOUT_MS,
        VIEW_DUR_MULTIPLIER, VIEW_DUR_SAMPLE_SIZE, VIEW_DUR_START_TIMEOUT_MS,
    },
    select_chain::SelectChainReceiver,
    session_info_provider::{SessionAuthorityProvider, SessionInfoService},
    session_rotation_worker::{SessionChanged, SessionChangedReceiver, SessionRotationService},
    state::{ConsensusProvider, LeaderProvider, QcProvider, StateChanged, StateService},
    timer::{Timer, ViewDuration},
};

const LOG_TARGET: &str = "sc-consensus-hotstuff::core";
const DEFAULT_FORCE_PROPOSE_INTERVAL_MS: u64 = 100;

pub(crate) fn timeout_high_qc_evidence<B: BlockT>(
    timeout: &Timeout<B>,
) -> HotstuffResult<(&QC<B>, &AggregateSignature)> {
    let local_high_qc = timeout
        .local_high_qc
        .as_ref()
        .ok_or_else(|| HotstuffError::Other("Missing local high QC".to_string()))?;
    let local_high_qc_sig = timeout
        .local_high_qc_sig
        .as_ref()
        .ok_or_else(|| HotstuffError::Other("Missing local high QC signature".to_string()))?;

    Ok((local_high_qc, local_high_qc_sig))
}

/// Validator core that handles full consensus logic
/// This includes timer management, consensus messages, chain events, and session rotation
/// It requires authorities network to be established
pub struct ValidatorCore<B, CR, BE, C, BI, N>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    BI: ConsensusBlockImport<B> + 'static,
    N: Network<B> + Sync + 'static,
{
    network: HotstuffNetworkSender<B, N>,
    crypto: CR,
    state_service: StateService<B>,
    session_info_service: Arc<SessionInfoService<B>>,
    peer_prov: PeerProviderService,
    client: Arc<C>,
    block_importer: BI,
    block_syncer: BlockSyncerService<B>,
    // from hotstuff_network
    consensus_msg_rx: Receiver<ConsensusMessage<B>>,
    // to proposer
    proposer_op_tx: Sender<ConsensusOp<B>>,
    // to pacemaker
    pacemaker_op_tx: Sender<ConsensusOp<B>>,
    // to select_chain
    best_block_request_rx: SelectChainReceiver<B>,
    session_rotation_service: SessionRotationService<B>,
    // from session rotation worker
    session_changed_rx: SessionChangedReceiver<B>,
    peer_lifecycle_rx: UnboundedReceiver<PeerLifecycleEvent>,
    // timer
    timer: Timer,
    view_duration: ViewDuration,
    // for agg high qc
    high_qc_aggregator: HighQcAggregator<B>,
    // latest vote view
    last_vote_view: ViewNumber,
    // metrics
    metrics: MetricsOpt,
    // track first vote time for the current view to measure QC generation time
    // Only stores (view, start_time) for the latest view
    vote_start_time: Option<(ViewNumber, std::time::Instant)>,
    timeout_start_time: Option<(ViewNumber, std::time::Instant)>,
    _phantom: PhantomData<BE>,
}

impl<B, CR, BE, C, BI, N> Unpin for ValidatorCore<B, CR, BE, C, BI, N>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    BI: ConsensusBlockImport<B> + 'static,
    N: Network<B> + Sync + 'static,
{
}

impl<B, CR, BE, C, BI, N> ValidatorCore<B, CR, BE, C, BI, N>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
    BI: ConsensusBlockImport<B> + 'static,
    N: Network<B> + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    /// Creates a validator core with all consensus services, channels, timer state, and runtime dependencies.
    pub fn new(
        network: HotstuffNetworkSender<B, N>,
        crypto: CR,
        state_service: StateService<B>,
        session_info_service: Arc<SessionInfoService<B>>,
        peer_prov: PeerProviderService,
        client: Arc<C>,
        block_importer: BI,
        block_syncer: BlockSyncerService<B>,
        metrics: MetricsOpt,
        consensus_msg_rx: Receiver<ConsensusMessage<B>>,
        proposer_op_tx: Sender<ConsensusOp<B>>,
        pacemaker_op_tx: Sender<ConsensusOp<B>>,
        best_block_request_rx: SelectChainReceiver<B>,
        session_rotation_service: SessionRotationService<B>,
        session_changed_rx: SessionChangedReceiver<B>,
        peer_lifecycle_rx: UnboundedReceiver<PeerLifecycleEvent>,
    ) -> Self {
        let view_duration = ViewDuration::new(
            VIEW_DUR_SAMPLE_SIZE,
            VIEW_DUR_START_TIMEOUT_MS,
            VIEW_DUR_MAX_TIMEOUT_MS,
            VIEW_DUR_MIN_TIMEOUT_MS,
            VIEW_DUR_MULTIPLIER,
        );
        let timer = Timer::new();

        Self {
            network,
            crypto,
            state_service,
            session_info_service,
            peer_prov,
            client,
            block_importer,
            block_syncer,
            consensus_msg_rx,
            proposer_op_tx,
            pacemaker_op_tx,
            best_block_request_rx,
            session_rotation_service,
            session_changed_rx,
            peer_lifecycle_rx,
            metrics,
            timer,
            view_duration,
            high_qc_aggregator: HighQcAggregator::new(),
            last_vote_view: GENESIS_VIEW,
            vote_start_time: None,
            timeout_start_time: None,
            _phantom: PhantomData,
        }
    }

    /// Runs the validator core event loop, processing consensus messages, session events, peer events, chain notifications, and local timeouts.
    pub async fn run(mut self) {
        log::info!(
            target: LOG_TARGET,
            "Start Hotstuff, local_peer_id: {}",
            self.network.local_peer_id(),
        );

        if let Err(e) = self.prepare_initial_authority_peers().await {
            log::error!(target: LOG_TARGET, "Hotstuff startup aborted: {}", e);
            return;
        }

        if let Err(e) = self.init_state_from_storage().await {
            log::trace!(target: LOG_TARGET, "Init State error: {e}");
        } else {
            log::info!(target: LOG_TARGET, "Init State done");
        }

        if self.is_auth_for_cur_session().await {
            self.timer.start(self.view_duration.duration());
            self.view_duration.view_started();
        }

        let mut chain_events = self.client.chain_status_notifier();
        let mut reserved_peers_refresh_tick = tokio::time::interval(
            std::time::Duration::from_secs(REFRESH_RESERVED_PEERS_INTERVAL_SECS),
        );
        reserved_peers_refresh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let res = tokio::select! {
                Some(msg) = self.consensus_msg_rx.recv() => match msg {
                    ConsensusMessage::Proposal(proposal) => self.handle_propose(proposal).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(timeout).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(vote).await,
                    ConsensusMessage::NewView(new_view) => self.handle_new_view(new_view).await,
                },
                Some(best_block_response_tx) = self.best_block_request_rx.recv() => {
                    self.handle_best_block_request(best_block_response_tx).await
                },

                session_event = self.session_changed_rx.recv() => match session_event {
                    Some(changed) => self.on_session_changed(changed).await,
                    None => Ok(()),
                },
                peer_event = self.peer_lifecycle_rx.recv() => match peer_event {
                    Some(event) => self.on_peer_lifecycle_event(event).await,
                    None => Ok(()),
                },
                _ = reserved_peers_refresh_tick.tick() => {
                    self.refresh_joined_authority_peers_for_current_session("periodic").await
                },
                Ok(chain_event) = chain_events.next() => match chain_event {
                    ChainStatusNotification::BlockImported((hash, number)) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "Imported event, new best block #{} ({:?})",
                            number, hash
                        );
                        // Notify block_syncer to remove blocks at or below this height from retry queue
                        self.block_syncer.notify_block_imported(hash, number).await;
                        Ok(())
                    },
                    _ => {
                        Ok(())
                    },
                },
                () = &mut self.timer => self.local_timeout_view().await,
            };
            match res {
                Ok(()) => (),
                Err(e) => log::log!(target: LOG_TARGET, e.log_level(), "{}", e),
            }
        }
    }

    // Startup

    /// Waits for authority discovery and initializes the consensus gossip active peer set before entering the main loop.
    async fn prepare_initial_authority_peers(&mut self) -> HotstuffResult<()> {
        // Start with a quorum; the main loop periodically refreshes any missing authority peers.
        self.enough_authorities_discovered().await;
        // for debugging
        self.print_peer_validator_map().await;
        self.check_peer_addr_conflicts().await?;

        // set initial active_validators to gossip validator
        let session_index = self.session_info_service.current_session_index().await;
        let _ = self
            .refresh_joined_authority_peers_for_session(session_index, "prepare_initial")
            .await;

        let joined_authority_peers_state = self.network.joined_authority_peers_state().await;
        log::debug!(
            target: LOG_TARGET,
            "joined_authority_peers in gossip validator: {:?}, reserved_peers for consensus protocol: {}",
            joined_authority_peers_state.gossip_peers(),
            self.network.protocol_reserved_peers_len().await
        );
        Ok(())
    }

    /// Waits until a quorum of current-session authorities has discoverable peer information.
    async fn enough_authorities_discovered(&mut self) {
        loop {
            let session_index = self.session_info_service.current_session_index().await;
            let Some(authorities) = self.session_info_service.authorities(session_index).await
            else {
                log::warn!(
                    target: LOG_TARGET,
                    "Failed to get authorities for session {}, retrying discovery check",
                    session_index
                );
                tokio::time::sleep(PEER_WAIT_INTERVAL).await;
                continue;
            };

            // Count current-session validators only, including this node. Discovery's runtime
            // API also returns next-session keys, which must not contribute to this quorum.
            let actual = self
                .peer_prov
                .get_peer_infos_with_self(&authorities, session_index)
                .await
                .len();
            let quorum = self
                .session_info_service
                .quorum_voting_power(session_index)
                .await;

            log::trace!(
                target: LOG_TARGET,
                "wait for enough authorities discovered, {}/{}, quorum: {}",
                actual,
                authorities.len(),
                quorum
            );
            if quorum > 0 && actual >= quorum {
                return;
            }

            tokio::time::sleep(PEER_WAIT_INTERVAL).await;
        }
    }

    /// Initializes consensus state from stored QC/TC data and sends an initial NewView hint when possible.
    async fn init_state_from_storage(&mut self) -> HotstuffResult<()> {
        let best_hash = self.client.info().best_hash;
        let qc_for_best = self.state_service.get_qc_of_block(&best_hash).await;
        let _ = self.try_advance_view(qc_for_best.as_ref(), None).await;
        if let Some(qc) = qc_for_best {
            let _ = self.block_importer.try_commit(&qc).await?;
        }

        if let Some(local_id) = self.session_info_service.local_validator_id().await {
            let current_session_index = self.session_info_service.current_session_index().await;
            // NOTE: This is useless since we cannot ensure all the validators start at the same time,
            // some validators cannot receive this new_view msg because it has not fully started yet,
            // so the real view synchronization relies on broadcast timeout messages.
            self.proposer_op_tx
                .try_send(ConsensusOp::NewView(NewViewParams {
                    view: self.state_service.cur_view().await,
                    session_index: current_session_index,
                    leader_id: local_id.clone(),
                    sync_info: SyncInfo::new()
                        .with_tc(self.state_service.high_tc().await)
                        .with_qc(self.state_service.high_qc().await),
                }))
                .map_err(|e| HotstuffError::Other(e.to_string()))?;
        }

        Ok(())
    }

    // Proposals and votes

    /// Processes an incoming proposal, verifies its certificates and leader, imports the proposal block, and sends a vote when allowed.
    async fn handle_propose(&mut self, proposal: Proposal<B>) -> HotstuffResult<()> {
        log::trace!(
            target: LOG_TARGET,
            "[handle_propose], view: {}, leader: {}",
            proposal.view,
            proposal.leader_id,
        );

        // Verify tc and agg_qc.high_qc(or new_qc) and advance view.
        self.apply_new_view(proposal.new_view()).await?;

        // try commit
        let _ = self.block_importer.try_commit(&proposal.qc).await;

        if self.state_service.cur_view().await > proposal.view {
            return Err(HotstuffError::OldView(
                "handle_propose".to_string(),
                proposal.view,
                self.state_service.cur_view().await,
            ));
        }

        // verify view only for proposal, not for certs
        if !self.can_vote_for_view(proposal.view) {
            return Err(HotstuffError::Other(format!(
                "view {} voting has stopped, latest view: {}",
                proposal.view, self.last_vote_view
            )));
        }

        // Verifing leader should be after the certs verification and view change as
        // the correctness of leader identification only matters in terms of proposal payload
        // instead of the certs.
        // The context for leader checking should be the time when
        // we were selecting leader for votes or timeouts collection before.

        // Build leader election context using builder pattern
        // The trigger (Vote/Timeout) determines the leader election strategy
        let is_first_block_of_session = self
            .session_info_service
            .is_first_block_of_session(proposal.payload.block_number)
            .await;

        let election_ctx = LeaderElectionContextBuilder::new(
            proposal.session_index,
            is_first_block_of_session,
            proposal.tc.is_some(), // has_timeout_cert
        )
        .build();

        // Verify leader using the abstracted validator
        let leader_validator = LeaderValidator::new(
            &self.state_service,
            self.session_info_service.as_ref(),
            &self.crypto,
        );
        leader_validator
            .verify_proposal_leader(&proposal, &election_ctx)
            .await?;

        // Update metrics
        if let Some(ref m) = self.metrics.0 {
            m.update_pcstate(
                self.state_service.cur_view().await,
                self.state_service.high_qc().await.view,
                self.state_service.high_tc().await.view,
                proposal.payload.extrinsics.len() as u64,
                self.view_duration.duration(),
                self.session_info_service
                    .current_session_index()
                    .await
                    .into(),
            );
        }

        // Verify fork confliction
        self.check_proposal_import_rule(&proposal).await?;

        // Build block, execute txs and put it on chain
        let block_hash = measure_time!(format!("import_proposal view: {}", proposal.view), {
            self.block_importer.import_proposal(&proposal).await?
        });

        log::info!(
            target: LOG_TARGET,
            "🤝 HotstuffState HighQC: {} HighTC: {} CurView: {} Number: {}-{} Hash: {} Txs: {} Dur: {}ms Leader: {}",
            self.state_service.high_qc().await.view,
            self.state_service.high_tc().await.view,
            self.state_service.cur_view().await,
            self.session_info_service.current_session_index().await,
            proposal.payload.block_number,
            block_hash,
            proposal.payload.extrinsics.len(),
            self.view_duration.duration(),
            proposal.leader_id,
        );

        // Safety check: ensure that proposal.qc.block_hash is on the same branch as the locked block(high_qc.block).
        // Forks may still occur under this condition, but at most at the same level
        // as the best block, and they will not lead to conflicting finalizations.
        self.check_fork_conflict(&block_hash).await?;

        // vote
        let vote = self
            .generate_vote(
                proposal.view,
                proposal.session_index,
                &block_hash,
                proposal.payload.block_number,
                self.session_info_service
                    .local_validator_id()
                    .await
                    .ok_or_else(|| {
                        HotstuffError::Other("Failed to get local validator id".to_string())
                    })?,
            )
            .await?;

        let current_session_index = self.session_info_service.current_session_index().await;
        let leader_id = self
            .state_service
            .get_leader(
                self.state_service.cur_view().await + 1,
                current_session_index,
            )
            .await;
        let leader_disc_id = self
            .session_info_service
            .get_auth_disc_id(current_session_index, &leader_id)
            .await
            .ok_or_else(|| HotstuffError::Other("Failed to get leader discovery id".to_string()))?;
        let leader_peer_id = match self
            .peer_prov
            .get_peer_info(&leader_disc_id, current_session_index)
            .await
        {
            Some(info) => info.peer_id,
            None => {
                return Err(HotstuffError::PeerInfoNotFound(leader_id));
            }
        };

        log::trace!(
            target: LOG_TARGET,
            "📤 Sending vote to leader, session: {}, view: {}, leader_id: {}, follower_id: {}, cur_dur: {}ms",
            current_session_index,
            proposal.view,
            leader_id,
            vote.follower_id,
            self.view_duration.duration(),
        );
        self.network
            .send_message(vec![leader_peer_id], ConsensusMessage::Vote(vote));
        self.metrics.set_latest_vote_view(proposal.view);

        self.stop_vote_for_view(proposal.view);

        Ok(())
    }

    /// Checks whether the proposal satisfies the local voting rule for the current view.
    async fn check_proposal_import_rule(&mut self, proposal: &Proposal<B>) -> HotstuffResult<()> {
        let current_view = self.state_service.cur_view().await;
        check_proposal_import_rule_logic(proposal, current_view)
    }

    /// Checks whether the imported proposal block stays on the current best branch before voting.
    async fn check_fork_conflict(&self, block_hash: &B::Hash) -> HotstuffResult<()> {
        let locked_block_hash = self.state_service.high_qc().await.block_hash;
        if extended_from::<B, BE, C>(self.client.as_ref(), block_hash, &locked_block_hash)? {
            return Ok(());
        }

        Err(HotstuffError::InvalidVoteRule(format!(
            "imported block {:?} is not extended from high_qc.block {:?}",
            block_hash, &locked_block_hash,
        )))
    }

    /// Builds and signs a vote for the given proposal block and view.
    async fn generate_vote(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        block_hash: &B::Hash,
        block_number: NumberFor<B>,
        follower_id: ValidatorId,
    ) -> HotstuffResult<Vote<B>> {
        let mut vote = Vote::<B>::new(*block_hash, block_number, view, session_index, follower_id);
        let vote_msg = vote_qc_payload_hash::<B>(session_index, view, *block_hash, block_number);
        let block_sig = self
            .crypto
            .sign(&vote_msg)
            .await
            .map_err(|e| HotstuffError::SignFailed(e.to_string()))?;
        vote.set_partial_sig(block_sig);
        Ok(vote)
    }

    /// Processes a vote, aggregates signatures into a QC, advances view state, and triggers proposal generation when quorum is reached.
    async fn handle_vote(&mut self, vote: Vote<B>) -> HotstuffResult<()> {
        // Record first vote time for this view (only store latest view)
        let first_vote_time = match &self.vote_start_time {
            Some((stored_view, stored_time)) if *stored_view == vote.view => *stored_time,
            _ => {
                let now = std::time::Instant::now();
                self.vote_start_time = Some((vote.view, now));
                now
            }
        };

        log::trace!(
            target: LOG_TARGET,
            "[handle_vote], view: {}, number: {}-{}, follower_id: {}",
            vote.view,
            vote.session_index,
            vote.block_number,
            vote.follower_id
        );

        if self.block_syncer.is_major_syncing().await {
            return Err(HotstuffError::Other("is major syncing".to_string()));
        }

        if vote.view < self.state_service.cur_view().await {
            return Err(HotstuffError::Other(format!(
                "view is old {}, cur: {}",
                vote.view,
                self.state_service.cur_view().await
            )));
        }

        let local_block_number = self.resolve_local_block_number(vote.block_hash)?;
        if vote.block_number != local_block_number {
            return Err(HotstuffError::InvalidBlockNumber(
                local_block_number.to_string(),
                vote.block_number.to_string(),
            ));
        }

        let vote_msg = vote_qc_payload_hash::<B>(
            vote.session_index,
            vote.view,
            vote.block_hash,
            vote.block_number,
        );

        let new_qc = {
            let agg_sig = match self
                .crypto
                .collect_partial_sig(
                    vote.view,
                    &vote_msg,
                    vote.partial_sig.ok_or_else(|| {
                        HotstuffError::Other("Missing partial signature".to_string())
                    })?,
                    vote.session_index,
                )
                .await
            {
                Some(sig) => {
                    if !sig.is_valid() {
                        return Err(HotstuffError::InvalidSignature(vote.view));
                    }
                    sig
                }
                None => {
                    let progress = self
                        .crypto
                        .collecting_progress(vote.view, &vote_msg, vote.session_index)
                        .await;
                    return Err(HotstuffError::LtQuorum(vote.view, progress.0, progress.1));
                }
            };

            QC::<B>::new(
                vote.block_hash,
                vote.block_number,
                vote.view,
                vote.session_index,
                agg_sig,
            )
        };

        self.try_advance_view(Some(&new_qc), None).await;

        let qc_generation_time = first_vote_time.elapsed().as_millis() as u64;
        self.metrics.set_qc_generation_time_ms(qc_generation_time);

        // Clean up the tracking entry if it matches this view
        if matches!(self.vote_start_time, Some((v, _)) if v == new_qc.view) {
            self.vote_start_time = None;
        }

        log::debug!(
            target: LOG_TARGET,
            "🎯 QC generated in {}ms, view: {}, number: {}-{}, participants: {}",
            qc_generation_time,
            new_qc.view,
            new_qc.session_index,
            new_qc.block_number,
            new_qc.agg_sig.participants().len(),
        );

        // Make sure that qc.block exsits for leader, if not,
        // try sync it from others asynchrously
        match self.block_importer.block_exist(new_qc.block_hash).await {
            Ok(_) => {}
            Err(_e) => {
                // Request block sync through BlockSyncer (with deduplication)
                // let peers = self.sync_target_peers().await;
                // self.block_syncer
                //     .sync_block(peers, new_qc.block_hash, new_qc.block_number)
                //     .await;
            }
        }
        // If importing qc still failed(largely because of lacking block)
        // don't return, make sure the qc will be broadcasted
        match self.block_importer.import_qc(new_qc.clone()).await {
            Ok(()) => {
                let _ = self
                    .session_rotation_service
                    .try_advance_session(new_qc.block_number)
                    .await;
            }
            Err(e) => {
                log::warn!(
                    target: LOG_TARGET,
                    "leader import new qc failed, error: {e}",
                );
            }
        }

        let local_id = self
            .session_info_service
            .local_validator_id()
            .await
            .ok_or_else(|| HotstuffError::Other("Failed to get local validator id".to_string()))?;
        let current_session_index = self.session_info_service.current_session_index().await;
        self.proposer_op_tx
            .send(ConsensusOp::Propose(ProposeParams {
                view: self.state_service.cur_view().await,
                session_index: current_session_index,
                leader_id: local_id,
                validator_ids_hash: self
                    .session_info_service
                    .validator_ids_hash(current_session_index)
                    .await,
                sync_info: SyncInfo::new().with_qc(self.state_service.high_qc().await),
                force_propose: self.force_generate_proposal(),
            }))
            .await
            .map_err(|e| HotstuffError::Other(e.to_string()))?;

        log::trace!(
            target: LOG_TARGET,
            "send to proposer, session: {}, view: {}",
            current_session_index,
            self.state_service.cur_view().await,
        );

        Ok(())
    }

    /// Marks the given view as no longer votable to prevent duplicate voting in old views.
    fn stop_vote_for_view(&mut self, view: ViewNumber) {
        if self.last_vote_view < view {
            self.last_vote_view = view;
        }
    }

    /// Returns whether the node is still allowed to vote for the given view.
    fn can_vote_for_view(&self, view: ViewNumber) -> bool {
        self.last_vote_view < view
    }

    // New views and certificate verification

    /// Processes a NewView message and attempts to commit with the carried QC after applying the view change.
    async fn handle_new_view(&mut self, new_view: NewView<B>) -> HotstuffResult<()> {
        self.apply_new_view(new_view.clone()).await?;
        // try commit
        if let Some(qc_ref) = new_view.qc {
            self.block_importer.try_commit(&qc_ref).await?;
        }

        Ok(())
    }

    /// Verifies certificates in a NewView message, advances local view state, and imports the verified QC if present.
    async fn apply_new_view(&mut self, new_view: NewView<B>) -> HotstuffResult<()> {
        log::trace!(
            target: LOG_TARGET,
            "[handle_new_view], qc: {:?}, tc: {:?}, agg_qc.high_qc: {:?}",
            new_view.qc.as_ref().map(|qc| qc.view).unwrap_or(0),
            new_view.tc.as_ref().map(|tc| tc.view).unwrap_or(0),
            new_view
                .agg_qc
                .as_ref()
                .and_then(|a| a.high_qc())
                .map(|qc| qc.view)
                .unwrap_or(0),
        );

        if self.block_syncer.is_major_syncing().await {
            return Err(HotstuffError::Other("is major syncing".to_string()));
        }

        let current_session = self.session_info_service.current_session_index().await;
        self.verify_certs(
            new_view.qc.as_ref(),
            new_view.tc.as_ref(),
            new_view.agg_qc.as_ref(),
        )
        .await
        .map_err(|e| {
            log::error!(
                target: LOG_TARGET,
                "verify certs failed: {e}, cur_session: {}, new_view session: {}",
                current_session,
                new_view.session_index,
            );

            e
        })?;

        let (verified_qc, verified_tc) = match new_view.agg_qc.as_ref() {
            Some(agg_qc) => {
                let high_qc = agg_qc
                    .high_qc()
                    .ok_or(HotstuffError::InvalidAggQC(agg_qc.view))?;
                (Some(high_qc), new_view.tc.as_ref())
            }
            None => (new_view.qc.as_ref(), new_view.tc.as_ref()),
        };

        if verified_qc.is_some() || verified_tc.is_some() {
            self.try_advance_view(verified_qc, verified_tc).await;
        }

        if let Some(qc) = verified_qc {
            self.try_import_qc(&qc).await?
        }

        Ok(())
    }

    /// Verify the certs.
    async fn verify_certs(
        &self,
        qc: Option<&QC<B>>,
        tc: Option<&TC<B>>,
        agg_qc: Option<&AggQC<B>>,
    ) -> HotstuffResult<()> {
        if let Some(tc_ref) = tc {
            // An old TC cannot advance local state, so only newer TCs need verification.
            if tc_ref.view > self.state_service.high_tc().await.view {
                self.crypto.verify_tc(tc_ref).await.map_err(|e| match e {
                    CryptoError::InvalidSession(s) => HotstuffError::InvalidSession(s),
                    _ => HotstuffError::InvalidTC(tc_ref.view),
                })?;
            }
        }

        let current_high_qc = self.state_service.high_qc().await;

        if let Some(qc_ref) = qc {
            self.verify_qc_unless_known_old(qc_ref, &current_high_qc)
                .await?;
        }

        if let Some(agg_qc_ref) = agg_qc {
            self.crypto
                .verify_agg_qc(agg_qc_ref)
                .await
                .map_err(|e| match e {
                    CryptoError::InvalidSession(s) => HotstuffError::InvalidSession(s),
                    _ => HotstuffError::InvalidAggQC(agg_qc_ref.view),
                })?;

            let high_qc_ref = agg_qc_ref
                .high_qc()
                .ok_or(HotstuffError::InvalidAggQC(agg_qc_ref.view))?;

            if let Some(qc_ref) = qc {
                if qc_ref != high_qc_ref {
                    log::error!(
                        target: LOG_TARGET,
                        "new_view carries mismatched qc and agg_qc.high_qc"
                    );
                    return Err(HotstuffError::InvalidAggQC(agg_qc_ref.view));
                }
            }

            self.verify_qc_unless_known_old(high_qc_ref, &current_high_qc)
                .await?;
        }

        Ok(())
    }

    async fn verify_qc_unless_known_old(
        &self,
        qc: &QC<B>,
        current_high_qc: &QC<B>,
    ) -> HotstuffResult<()> {
        if qc.view <= current_high_qc.view {
            // Old QCs are trusted only when they are already known locally.
            // Otherwise a forged old QC could be attached to an existing block.
            let known_qc = self.state_service.get_qc_of_block(&qc.block_hash).await;
            if known_qc.as_ref() == Some(qc) || qc == current_high_qc {
                return Ok(());
            }
        }

        self.crypto.verify_qc(qc).await.map_err(|e| match e {
            CryptoError::InvalidSession(s) => HotstuffError::InvalidSession(s),
            _ => HotstuffError::InvalidQC,
        })
    }

    /// Imports a QC when its block is available and tries session advancement after import.
    /// Returns an error if the block is unavailable.
    async fn try_import_qc(&mut self, qc: &QC<B>) -> HotstuffResult<()> {
        match self.block_importer.block_exist(qc.block_hash).await {
            Ok(_) => {}
            Err(e) => {
                // Request block sync through BlockSyncer (with deduplication)
                // let peers = self.sync_target_peers().await;
                // self.block_syncer
                //     .sync_block(peers, qc.block_hash, qc.block_number)
                //     .await;
                return Err(e);
            }
        }

        // update the best number
        if self
            .state_service
            .get_qc_of_block(&qc.block_hash)
            .await
            .is_none()
        {
            let local_block_number = self.resolve_local_block_number(qc.block_hash)?;
            if qc.block_number != local_block_number {
                return Err(HotstuffError::InvalidBlockNumber(
                    local_block_number.to_string(),
                    qc.block_number.to_string(),
                ));
            }

            log::trace!(
                target: LOG_TARGET,
                "import new QC, qc.block_hash: {}, qc.view: {}",
                qc.block_hash,
                qc.view
            );
            self.block_importer.import_qc(qc.clone()).await?;
            let _ = self
                .session_rotation_service
                .try_advance_session(qc.block_number)
                .await;
        }

        Ok(())
    }

    // Timeouts and view advancement

    /// Processes timeout messages, builds TC/AggQC when quorum is reached, advances view state, and drives timeout-path proposal or NewView actions.
    async fn handle_timeout(&mut self, timeout: Timeout<B>) -> HotstuffResult<()> {
        // Record first timeout time for this view (only store latest view)
        let first_timeout_time = match &self.timeout_start_time {
            Some((stored_view, stored_time)) if *stored_view == timeout.view => *stored_time,
            _ => {
                let now = std::time::Instant::now();
                self.timeout_start_time = Some((timeout.view, now));
                now
            }
        };

        log::trace!(
            target: LOG_TARGET,
            "[handle_timeout], view: {}, follower_id: {}, has_local_qc: {}",
            timeout.view,
            timeout.follower_id,
            timeout.local_high_qc.is_some(),
        );

        if self.block_syncer.is_major_syncing().await {
            return Err(HotstuffError::Other("is major syncing".to_string()));
        }

        // timeout.view should be >= self.state.cur_view
        if timeout.view < self.state_service.cur_view().await {
            return Err(HotstuffError::OldView(
                "handle_timeout".to_string(),
                timeout.view,
                self.state_service.cur_view().await,
            ));
        }

        // Sync local qc in advance in case timeout is less than 2f+1 and agg_qc will never be generated
        if let Some(ref local_high_qc) = timeout.local_high_qc {
            if local_high_qc > &self.state_service.high_qc().await {
                match self.crypto.verify_qc(local_high_qc).await {
                    Ok(_) => {
                        self.try_advance_view(Some(&local_high_qc), None).await;
                    }
                    Err(e) => log::warn!(
                        target: LOG_TARGET,
                        "handle_timeout verify local_high_qc: {} failed: {}",
                        local_high_qc.view, e,
                    ),
                }
            }

            // sync view by local high tc if it exists
            // mainly for validators restarting based on existing db
            if let Some(ref local_high_tc) = timeout.local_high_tc {
                if local_high_tc > &self.state_service.high_tc().await {
                    match self.crypto.verify_tc(local_high_tc).await {
                        Ok(_) => self.try_advance_view(None, Some(&local_high_tc)).await,
                        Err(e) => log::warn!(
                            target: LOG_TARGET,
                            "handle_timeout verify local_high_tc: {} failed: {}",
                            local_high_tc.view, e,
                        ),
                    }
                }
            }
        }

        // generate tc and agg_qc
        let (tc, agg_qc_opt) = self.generate_tc_and_agg_qc(&timeout).await?;

        let tc_generation_time = first_timeout_time.elapsed().as_millis() as u64;
        self.metrics.set_tc_generation_time_ms(tc_generation_time);

        // Clean up the tracking entry if it matches this view
        if matches!(self.timeout_start_time, Some((v, _)) if v == timeout.view) {
            self.timeout_start_time = None;
        }

        match agg_qc_opt {
            Some(ref agg_qc) => {
                log::trace!(
                    target: LOG_TARGET,
                    "generate tc and agg_qc, view: {}, tc: {:?}, tc_len: {:?}, agg_qc: {:?}, agg_qc_len: {:?}",
                    timeout.view,
                    tc.view,
                    tc.agg_sig.participants().len(),
                    agg_qc.view,
                    agg_qc.qcs.len(),
                );

                // We just need to verify the highest qc in agg_qc before advancing the view
                // as only the high_qc makes sense
                // TC verification is unnecessary as it is generated by validator itself
                if let Some(ref high_qc) = agg_qc.high_qc() {
                    if *high_qc > &self.state_service.high_qc().await {
                        self.crypto
                            .verify_qc(high_qc)
                            .await
                            .map_err(|_| HotstuffError::InvalidQC)?;

                        self.try_advance_view(Some(high_qc), None).await;
                    }
                    // Try import high_qc after agg_qc is generated
                    let _ = self.try_import_qc(high_qc).await;
                }
            }
            None => {
                log::trace!(
                    target: LOG_TARGET,
                    "generate tc only, view: {}, tc: {:?}, tc_len: {:?}",
                    timeout.view,
                    tc.view,
                    tc.agg_sig.participants().len(),
                );
            }
        }

        // Since the leader is associated with finalize, and finalize itself involves asynchronous scenarios (such as synchronization),
        // it is highly likely that the leaders elected by the validators may be inconsistent at a certain moment.
        // However, they will eventually converge to consistency; it merely requires waiting for another timeout period.

        // propose if I'm the leader
        let local_id = self
            .session_info_service
            .local_validator_id()
            .await
            .ok_or_else(|| HotstuffError::Other("Failed to get local validator id".to_string()))?;
        let current_session_index = self.session_info_service.current_session_index().await;
        let (leader_id, _) = self
            .state_service
            .get_leader_with_backups(
                self.state_service.cur_view().await,
                current_session_index,
                0,
            )
            .await;
        if local_id == leader_id {
            // New propose should be extended from agg_qc.high_qc
            // Q: Can agg_qc.high_qc < self.state.high_qc?
            // A: Unlikely, as no leader will advance view arbitrarily when a qc is generated
            //    all the validators will apply the QC together, so agg_qc must have the real high_qc of the network
            self.proposer_op_tx
                .send(ConsensusOp::Propose(ProposeParams {
                    view: self.state_service.cur_view().await,
                    session_index: current_session_index,
                    leader_id: local_id.clone(),
                    validator_ids_hash: self
                        .session_info_service
                        .validator_ids_hash(current_session_index)
                        .await,
                    sync_info: SyncInfo::new()
                        // .with_qc(self.state_service.high_qc().await)
                        .with_qc(
                            agg_qc_opt
                                .as_ref()
                                .and_then(|opt| opt.high_qc())
                                .cloned()
                                .ok_or_else(|| {
                                    HotstuffError::Other("Missing high qc in agg_qc".to_string())
                                })?,
                        )
                        .with_tc(tc)
                        .with_agg_qc(
                            agg_qc_opt.ok_or_else(|| {
                                HotstuffError::Other("Missing agg_qc".to_string())
                            })?,
                        ),
                    force_propose: self.force_generate_proposal(),
                }))
                .await
                .map_err(|e| HotstuffError::Other(e.to_string()))?;
            log::trace!(
                target: LOG_TARGET,
                "I'm the leader, send propose command to proposer, view: {}, leader_id: {}",
                self.state_service.cur_view().await,
                local_id,
            );
        }

        Ok(())
    }

    /// Generate TC and optionally AggQC from timeout message
    /// This function handles:
    /// 1. Verify view signature
    /// 2. Collect partial signatures to form TC
    /// 3. If local_high_qc exists, aggregate them to form AggQC
    /// 4. Advance view with the generated TC
    pub async fn generate_tc_and_agg_qc(
        &mut self,
        timeout: &Timeout<B>,
    ) -> HotstuffResult<(TC<B>, Option<AggQC<B>>)> {
        let timeout_msg = timeout_tc_payload_hash::<B>(timeout.session_index, timeout.view);

        // verify view sig
        let view_sig = timeout
            .view_sig
            .as_ref()
            .ok_or_else(|| HotstuffError::Other("Missing view signature".to_string()))?;

        if self
            .crypto
            .verify(view_sig, &timeout_msg, timeout.session_index)
            .await
            .is_err()
        {
            log::warn!(
                target: LOG_TARGET,
                "view sig verify failed, view: {}", timeout.view);
            return Err(HotstuffError::InvalidSignature(timeout.view));
        }

        // collect local high qc info
        let (local_high_qc, local_high_qc_sig) = timeout_high_qc_evidence(timeout)?;
        let high_qc_msg = high_qc_in_timeout_payload_hash::<B>(
            timeout.session_index,
            timeout.view,
            local_high_qc.hash(),
        );
        let signer = self
            .crypto
            .verify_partial(local_high_qc_sig, &high_qc_msg, timeout.session_index)
            .await
            .map_err(|_| {
                log::warn!(
                    target: LOG_TARGET,
                    "local high qc sig verify failed, timeout view: {}, high qc view: {}",
                    timeout.view,
                    local_high_qc.view,
                );
                HotstuffError::InvalidSignature(timeout.view)
            })?;

        self.high_qc_aggregator.collect(
            timeout.view,
            signer,
            local_high_qc.clone(),
            local_high_qc_sig.clone(),
        );

        // Collect partial signatures to form TC
        let agg_view_sig = match self
            .crypto
            .collect_partial_sig(
                timeout.view,
                &timeout_msg,
                view_sig.clone(),
                timeout.session_index,
            )
            .await
        {
            Some(sig) => {
                if !sig.is_valid() {
                    return Err(HotstuffError::InvalidSignature(timeout.view));
                }
                sig
            }
            None => {
                let progress = self
                    .crypto
                    .collecting_progress(timeout.view, &timeout_msg, timeout.session_index)
                    .await;
                return Err(HotstuffError::LtQuorum(
                    timeout.view,
                    progress.0,
                    progress.1,
                ));
            }
        };

        let tc = TC::<B>::new(timeout.view, timeout.session_index, agg_view_sig);
        self.try_advance_view(None, Some(&tc)).await;

        // Generate AggQC if local_high_qc exists
        let agg_qc_opt = if let Some(high_qc_view_aggregator) =
            self.high_qc_aggregator.get_view_aggregator(&timeout.view)
        {
            if high_qc_view_aggregator.local_high_qc_sigs().len()
                < self
                    .session_info_service
                    .quorum_voting_power(timeout.session_index)
                    .await
            {
                return Ok((tc, None));
            }

            let agg_high_qc_sig = self
                .crypto
                .combine(high_qc_view_aggregator.local_high_qc_sigs().as_slice())
                .await
                .map_err(|e| {
                    log::error!(
                        target: LOG_TARGET,
                        "create agg_qc failed, view: {}, err: {}",
                        high_qc_view_aggregator.high_qcs_view(), e,
                    );
                    HotstuffError::InvalidSignature(timeout.view)
                })?;

            let agg_qc = AggQC::<B>::new(
                high_qc_view_aggregator.high_qcs_view(),
                timeout.session_index,
                high_qc_view_aggregator.local_high_qcs().clone(),
                agg_high_qc_sig,
            );

            self.high_qc_aggregator.prune_to(timeout.view - 1);

            Some(agg_qc)
        } else {
            None
        };

        Ok((tc, agg_qc_opt))
    }

    // NOTE: Always remember to restart timer when the timeout msg is failed to be sent.
    /// Handles local view timeout by increasing timeout duration, selecting timeout targets, and sending a timeout command to the pacemaker.
    async fn local_timeout_view(&mut self) -> HotstuffResult<()> {
        let current_session_index = self.session_info_service.current_session_index().await;
        log::trace!(
            target: LOG_TARGET,
            "⏰ VIEW TIMEOUT! session: {}, view: {}, dur: {}ms → {}ms, high_qc: {}, high_tc: {}",
            current_session_index,
            self.state_service.cur_view().await,
            self.view_duration.duration(),
            (self.view_duration.duration() as f64 * VIEW_DUR_MULTIPLIER as f64) as u64,
            self.state_service.high_qc().await.view,
            self.state_service.high_tc().await.view,
        );

        // since the last timer has triggered, start a new timer
        self.stop_vote_for_view(self.state_service.cur_view().await);
        self.timer.stop();
        self.view_duration.view_timeout();

        if self.block_syncer.is_major_syncing().await {
            if self.is_auth_for_cur_session().await {
                self.timer.start(self.view_duration.duration());
            }
            return Err(HotstuffError::Other("is major syncing".to_string()));
        }

        let local_id = self
            .session_info_service
            .local_validator_id()
            .await
            .ok_or_else(|| HotstuffError::Other("Failed to get local validator id".to_string()))?;
        self.pacemaker_op_tx
            .send(ConsensusOp::Timeout(TimeoutParams {
                view: self.state_service.cur_view().await,
                session_index: current_session_index,
                local_id,
                high_qc: self.state_service.high_qc().await,
                high_tc_opt: Some(self.state_service.high_tc().await),
            }))
            .await
            .map_err(|e| HotstuffError::Other(e.to_string()))?;

        if self.is_auth_for_cur_session().await {
            self.timer.start(self.view_duration.duration());
        }
        Ok(())
    }

    /// Advances local view state with QC/TC updates and restarts the timeout timer after successful view changes.
    async fn try_advance_view(&mut self, qc: Option<&QC<B>>, tc: Option<&TC<B>>) {
        // adjust the timer or view_duration
        // there are three situations to reset the timer
        // 1. when the view has been changed by happy path, we'll stop the timer and start a new one
        // 2. when the view has been changed by unhappy path, we'll stop the timer and start a new one
        // 3. when the timer has triggered, a new timer should be set immediately
        match self.state_service.advance_view(qc, tc).await {
            Ok(StateChanged::HappyViewChangeTo(view)) => {
                log::trace!(
                    target: LOG_TARGET,
                    "VIEW_CHANGE by happy path, new view: {}",
                    view,
                );
                self.timer.stop();
                self.view_duration.view_succeeded();

                if self.is_auth_for_cur_session().await {
                    self.timer.start(self.view_duration.duration());
                    self.view_duration.view_started();
                }
            }
            Ok(StateChanged::UnhappyViewChangeTo(view)) => {
                log::trace!(
                    target: LOG_TARGET,
                    "VIEW_CHANGE by unhappy path, new view: {}",
                    view,
                );
                // restart the timer
                self.timer.stop();
                if self.is_auth_for_cur_session().await {
                    self.timer.start(self.view_duration.duration());
                    self.view_duration.view_started();
                }
            }
            _ => {}
        }

        self.network.set_view(self.state_service.cur_view().await);
    }

    /// Force propose block at least once every configured force-propose interval.
    fn force_generate_proposal(&self) -> bool {
        return self.view_duration.duration() >= self.force_propose_interval_ms();
    }

    fn force_propose_interval_ms(&self) -> u64 {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .force_propose_interval_ms(at)
            .unwrap_or_else(|error| {
                log::warn!(
                    target: LOG_TARGET,
                    "failed to fetch force-propose interval from runtime, using default {}ms: {}",
                    DEFAULT_FORCE_PROPOSE_INTERVAL_MS,
                    error,
                );
                DEFAULT_FORCE_PROPOSE_INTERVAL_MS
            })
    }

    // Best-block requests

    /// Replies with the header of the current best block derived from the local high QC.
    async fn handle_best_block_request(
        &mut self,
        best_block_response_tx: oneshot::Sender<B::Header>,
    ) -> HotstuffResult<()> {
        let high_qc_hash = self.state_service.high_qc().await.block_hash;
        let best_header = match self.client.header(high_qc_hash) {
            Ok(Some(header)) => header,
            Ok(None) => {
                log::warn!(
                    target: LOG_TARGET,
                    "high_qc block header missing for best block request, high_qc_hash: {}. Falling back to client best hash",
                    high_qc_hash,
                );
                return self
                    .handle_best_block_request_fallback(best_block_response_tx)
                    .await;
            }
            Err(error) => {
                log::warn!(
                    target: LOG_TARGET,
                    "failed to load high_qc header for best block request, high_qc_hash: {}, error: {}. Falling back to client best hash",
                    high_qc_hash,
                    error,
                );
                return self
                    .handle_best_block_request_fallback(best_block_response_tx)
                    .await;
            }
        };

        log::trace!("best block response: {:?}", high_qc_hash);

        let _ = best_block_response_tx.send(best_header);
        Ok(())
    }

    async fn handle_best_block_request_fallback(
        &mut self,
        best_block_response_tx: oneshot::Sender<B::Header>,
    ) -> HotstuffResult<()> {
        let fallback_hash = self.client.info().best_hash;
        let fallback_header = self
            .client
            .header(fallback_hash)
            .map_err(|e| HotstuffError::ClientImport(e.to_string()))?
            .ok_or_else(|| HotstuffError::MissingBlock(format!("hash: {}", fallback_hash)))?;

        let qc_for_best = self.state_service.get_qc_of_block(&fallback_hash).await;
        self.try_advance_view(qc_for_best.as_ref(), None).await;

        log::warn!(
            target: LOG_TARGET,
            "best block request fell back to client best hash: {}",
            fallback_hash,
        );

        let _ = best_block_response_tx.send(fallback_header);
        Ok(())
    }

    // Session changes and authority peers

    /// Applies a session rotation event, refreshes active peers, updates metrics, and resets the local timer when needed.
    async fn on_session_changed(&mut self, changed: SessionChanged<B>) -> HotstuffResult<()> {
        let to_session = changed.to_session;
        let Some(_) = self
            .refresh_joined_authority_peers_for_session(to_session, "session_changed")
            .await
        else {
            return Ok(());
        };

        let is_authority = self.is_auth_for_cur_session().await;

        log::debug!(
            target: LOG_TARGET,
            "session_changed applied at block #{:?}, from: {}, to: {}, new_joined_authority_peers_num: {}, is_authority_for_cur: {}",
            changed.block_number,
            changed.from_session,
            changed.to_session,
            self.network
                .joined_authority_peers_state()
                .await
                .gossip_peers()
                .len(),
            is_authority,
        );

        self.timer.stop();
        if self.is_auth_for_cur_session().await {
            log::trace!(
                target: LOG_TARGET,
                "Restart timer for new session",
            );
            self.timer.start(self.view_duration.duration());
            self.view_duration.view_started();
        }

        Ok(())
    }

    /// Returns whether the local node is an authority in the current session.
    async fn is_auth_for_cur_session(&self) -> bool {
        self.session_info_service
            .is_authoritiy_for_current_session()
            .await
    }

    /// Handles peer connect/disconnect events and triggers peer-set refresh on new peer connections.
    async fn on_peer_lifecycle_event(&mut self, event: PeerLifecycleEvent) -> HotstuffResult<()> {
        match event {
            PeerLifecycleEvent::NewPeer(peer_id) => {
                self.metrics.inc_peer_connected_total();
                log::info!(
                    target: LOG_TARGET,
                    "New peer connected: {:?}, trigger reserved peers refresh",
                    peer_id,
                );
                self.refresh_joined_authority_peers_for_current_session("new_peer")
                    .await
            }
            PeerLifecycleEvent::PeerDisconnected(peer_id) => {
                self.metrics.dec_peer_connected_total();
                log::warn!(
                    target: LOG_TARGET,
                    "Peer disconnected: {:?}, refresh peer metrics",
                    peer_id
                );
                // let _ = self
                //     .refresh_joined_authority_peers_for_current_session("disconnect_peer")
                //     .await;
                Ok(())
            }
        }
    }

    /// Refreshes consensus protocol joined peers for the current session when this node is an authority.
    async fn refresh_joined_authority_peers_for_current_session(
        &mut self,
        reason: &str,
    ) -> HotstuffResult<()> {
        let session_index = self.session_info_service.current_session_index().await;
        if !self.is_auth_for_cur_session().await {
            let authorities_count = self
                .session_info_service
                .authorities(session_index)
                .await
                .map(|authorities| authorities.len() as u64)
                .unwrap_or(0);
            let reserved_peers_count = self
                .network
                .joined_authority_peers_state()
                .await
                .reserved_peers()
                .len() as u64;

            self.metrics.update_session_rotation(
                session_index.into(),
                authorities_count,
                reserved_peers_count,
                false,
            );
            return Ok(());
        }

        let Some(authorities_len) = self
            .refresh_joined_authority_peers_for_session(session_index, reason)
            .await
        else {
            return Ok(());
        };

        let joined_authority_peers_state = self.network.joined_authority_peers_state().await;
        let joined_peers_count = joined_authority_peers_state.gossip_peers().len();
        let reserved_peers_count = joined_authority_peers_state.reserved_peers().len();

        log::debug!(
            target: LOG_TARGET,
            "Refreshed reserved peers, reason: {}, session: {}, authorities: {}, joined(incl_self): {}, reserved(exclude_self): {}",
            reason,
            session_index,
            authorities_len,
            joined_peers_count,
            reserved_peers_count,
        );
        Ok(())
    }

    /// Loads the authority set for the target session and updates the gossip active peer set.
    async fn refresh_joined_authority_peers_for_session(
        &mut self,
        session_index: SessionIndex,
        reason: &str,
    ) -> Option<usize> {
        let Some(authorities) = self.session_info_service.authorities(session_index).await else {
            log::warn!(
                target: LOG_TARGET,
                "Failed to get authorities for session {}, skip peer update, reason: {}",
                session_index,
                reason,
            );
            return None;
        };
        let authorities_len = authorities.len();
        let peers = self
            .peer_prov
            .get_peer_infos_with_self(&authorities, session_index)
            .await;
        self.network.set_joined_authority_peers(peers);
        self.check_joined_authority_peers(session_index, authorities_len, reason)
            .await;
        Some(authorities_len)
    }

    /// Checks reserved-peers status after peer-set update and reports metrics/warnings.
    async fn check_joined_authority_peers(
        &mut self,
        session_index: SessionIndex,
        authorities_len: usize,
        reason: &str,
    ) {
        let joined_authority_peers_state = self.network.joined_authority_peers_state().await;
        let joined_peers_count = joined_authority_peers_state.gossip_peers().len();
        let reserved_peers_count = joined_authority_peers_state.reserved_peers().len();
        let expected_reserved_peers_count = authorities_len.saturating_sub(1);
        let is_authority = self.is_auth_for_cur_session().await;

        self.metrics.update_session_rotation(
            session_index.into(),
            authorities_len as u64,
            reserved_peers_count as u64,
            is_authority,
        );

        if reserved_peers_count < expected_reserved_peers_count {
            log::warn!(
                target: LOG_TARGET,
                "Reserved peers count is lower than expected, reason: {}, session: {}, authorities: {}, expected_reserved(exclude_self): {}, reserved: {}, joined_authority_peers(incl_self): {}. Some peers may have been rejected by network backend (e.g. invalid/local/conflicting addresses).",
                reason,
                session_index,
                authorities_len,
                expected_reserved_peers_count,
                reserved_peers_count,
                joined_peers_count,
            );
        }
        if joined_peers_count < authorities_len {
            log::warn!(
                target: LOG_TARGET,
                "Joined peer set is smaller than authorities, reason: {}, session: {}, authorities: {}, joined_authority_peers(incl_self): {}. Some authority peer infos may be missing from discovery.",
                reason,
                session_index,
                authorities_len,
                joined_peers_count,
            );
        }
    }

    /// Detects whether any selected authority peer address collides with this node's local
    /// listening endpoint (same ip:port), which causes litep2p to reject it as a local address.
    async fn check_peer_addr_conflicts(&mut self) -> HotstuffResult<()> {
        let current_session_index = self.session_info_service.current_session_index().await;
        let Some(authorities) = self
            .session_info_service
            .authorities(current_session_index)
            .await
        else {
            return Ok(());
        };

        let local_peer_id = self.network.local_peer_id();
        let local_listen_addrs = self.network.listen_addresses();
        let local_endpoints: HashSet<(IpAddr, u16)> = local_listen_addrs
            .iter()
            .filter_map(extract_ip_port)
            .collect();

        if local_endpoints.is_empty() {
            return Ok(());
        }

        for (validator_id, (_, _, _, auth_disc_id)) in authorities {
            let Some(peer_info) = self
                .peer_prov
                .get_peer_info(&auth_disc_id, current_session_index)
                .await
            else {
                continue;
            };

            if peer_info.peer_id == local_peer_id {
                continue;
            }

            let Some((ip, port)) = extract_ip_port(&peer_info.multiaddr) else {
                continue;
            };

            if local_endpoints.contains(&(ip, port)) {
                return Err(HotstuffError::Other(format!(
                    "Startup peer address conflict detected: remote validator {} peer {:?} selected_addr {:?} conflicts with local listen endpoint {}:{}; litep2p may reject it as local address. Check local p2p port configuration.",
                    validator_id, peer_info.peer_id, peer_info.multiaddr, ip, port,
                )));
            }
        }
        Ok(())
    }

    // Diagnostics and helpers

    /// Logs the current mapping from discovered peer IDs to validator IDs for debugging.
    async fn print_peer_validator_map(&mut self) {
        let current_session_index = self.session_info_service.current_session_index().await;
        let Some(authorities) = self
            .session_info_service
            .authorities(current_session_index)
            .await
        else {
            log::warn!(
                target: LOG_TARGET,
                "Failed to get authorities for session {}, skipping peer map print",
                current_session_index
            );
            return;
        };

        for (validator_id, (_, _, _, auth_disc_id)) in authorities {
            if let Some(peer_info) = self
                .peer_prov
                .get_peer_info(&auth_disc_id, current_session_index)
                .await
            {
                log::debug!(target: LOG_TARGET, "peer: {:?} -> validator: {}", peer_info.peer_id, validator_id);
            }
        }
    }

    /// Logs a warning when the best block number does not match the expected current session mapping.
    #[allow(dead_code)]
    async fn print_session_check_log(&self) {
        let current_session_index = self.session_info_service.current_session_index().await;
        let best_number = self.client.info().best_number;
        if !self
            .session_info_service
            .is_number_match_session(best_number, current_session_index)
            .await
        {
            log::warn!(
                target: LOG_TARGET,
                "Wrong session, best number {} and current session: {} don't match",
                best_number,
                current_session_index,
            );
        }
    }

    fn resolve_local_block_number(&self, block_hash: B::Hash) -> HotstuffResult<NumberFor<B>> {
        self.client
            .header(block_hash)
            .map_err(|e| HotstuffError::ClientImport(e.to_string()))?
            .map(|header| *header.number())
            .ok_or_else(|| HotstuffError::MissingBlock(format!("hash: {}", block_hash)))
    }

    #[allow(dead_code)]
    async fn sync_target_peers(&self) -> Vec<sc_network::PeerId> {
        let joined_authority_peers_state = self.network.joined_authority_peers_state().await;
        joined_authority_peers_state
            .gossip_peers()
            .iter()
            .copied()
            .collect()
    }
}

fn extract_ip_port(addr: &Multiaddr) -> Option<(IpAddr, u16)> {
    let mut ip = None;
    let mut port = None;

    for proto in addr.iter() {
        match proto {
            MultiaddrProtocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
            MultiaddrProtocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
            MultiaddrProtocol::Tcp(p) => port = Some(p),
            MultiaddrProtocol::P2p(_) => break,
            _ => {}
        }
    }

    Some((ip?, port?))
}

/// Non-validator core that only handles session rotation
/// Listens to session change notifications and logs the observed rotations.
pub struct NonValidatorCore<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
{
    session_changed_rx: SessionChangedReceiver<B>,
    _phantom: PhantomData<(BE, C)>,
}

impl<B, BE, C> NonValidatorCore<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
{
    /// Creates a non-validator core that only consumes session change events.
    pub fn new(session_changed_rx: SessionChangedReceiver<B>) -> Self {
        Self {
            session_changed_rx,
            _phantom: PhantomData,
        }
    }

    /// Logs session rotation events observed by the non-validator core.
    async fn on_session_changed(&mut self, changed: SessionChanged<B>) {
        log::debug!(
            target: LOG_TARGET,
            "[NonValidator] session changed by block #{:?}: {} -> {}",
            changed.block_number,
            changed.from_session,
            changed.to_session,
        );
    }

    /// Listens to session change notifications until the channel closes.
    pub async fn run(mut self) {
        log::info!(
            target: LOG_TARGET,
            "NonValidatorCore started, waiting for session changed events"
        );

        loop {
            let event = self.session_changed_rx.recv().await;
            match event {
                Some(changed) => self.on_session_changed(changed).await,
                None => break,
            }
        }
    }
}

impl<B, BE, C> Unpin for NonValidatorCore<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + 'static,
    C: HotstuffClient<B, BE> + 'static,
    C::Api: HotstuffApi<B, NumberFor<B>> + BlockBuilderApi<B> + AuthorityDiscoveryApi<B>,
{
}

pub(crate) fn check_proposal_import_rule_logic<B: BlockT>(
    proposal: &Proposal<B>,
    current_view: ViewNumber,
) -> HotstuffResult<()> {
    if proposal.view != current_view {
        return Err(HotstuffError::Other(format!(
            "block conflict, view: {}",
            proposal.view
        )));
    }

    match (&proposal.tc, &proposal.agg_qc) {
        (None, None) if proposal.qc.view.checked_add(1) == Some(proposal.view) => Ok(()),
        (Some(tc), Some(agg_qc))
            if tc.view.checked_add(1) == Some(proposal.view)
                && agg_qc.view == tc.view
                && tc.session_index == proposal.session_index
                && agg_qc.session_index == proposal.session_index
                && proposal.qc.view <= tc.view
                && agg_qc.high_qc() == Some(&proposal.qc) =>
        {
            Ok(())
        }
        (None, None) => Err(HotstuffError::Other(format!(
            "block conflict, view: {}",
            proposal.view
        ))),
        _ => Err(HotstuffError::InvalidAggQC(proposal.view)),
    }
}
