use std::{marker::PhantomData, sync::Arc};

use codec::{Decode, Encode};
use sc_client_api::{AuxStore, Backend};
use sp_blockchain::Backend as ChainBackend;
use sp_consensus_hotstuff::HotstuffApi;
use sp_consensus_hotstuff::{AccountId, SessionIndex};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor, Zero};
use tokio::sync::{mpsc, oneshot};

use crate::{
    client::HotstuffClient,
    crypto::AggregateSignature,
    error::{HotstuffError, HotstuffResult},
    messages::{QC, TC},
    primitives::{
        default_validator_id, ValidatorId, ViewNumber, GENESIS_SESSION_INDEX, GENESIS_VIEW,
    },
    session_info_provider::{SessionAuthorityProvider, SessionInfoService},
};

const LOG_TARGET: &str = "sc-consensus-hotstuff::state";

fn shuffle_and_select_leader(
    validator_ids: Vec<ValidatorId>,
    view: ViewNumber,
    backup_num: usize,
) -> (ValidatorId, Vec<ValidatorId>) {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let seed = view;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut shuffled_ids = validator_ids.clone();
    for i in (1..shuffled_ids.len()).rev() {
        let j = rng.random_range(0..=i);
        shuffled_ids.swap(i, j);
    }
    let mut ids_iter = shuffled_ids.into_iter();
    let leader = ids_iter.next().unwrap_or_else(default_validator_id);
    let backups = if backup_num > 0 {
        ids_iter.take(backup_num).collect()
    } else {
        vec![]
    };
    (leader, backups)
}

const HIGH_TC_KEY: &[u8] = b"sc-consensus-hotstuff-high-tc";

fn session_boundary_candidates(
    intersection: Vec<ValidatorId>,
    preferred_signers: Vec<ValidatorId>,
    backup_num: usize,
) -> Vec<ValidatorId> {
    let required = 1 + backup_num;
    let preferred: Vec<ValidatorId> = intersection
        .iter()
        .filter(|id| preferred_signers.contains(*id))
        .cloned()
        .collect();

    if preferred.len() >= required {
        preferred
    } else {
        intersection
    }
}

// Service interfaces

#[async_trait::async_trait]
pub trait ConsensusProvider<B: BlockT> {
    async fn cur_view(&self) -> ViewNumber;
    async fn high_qc(&self) -> QC<B>;
    async fn high_tc(&self) -> TC<B>;
    async fn advance_view(
        &self,
        qc: Option<&QC<B>>,
        tc: Option<&TC<B>>,
    ) -> HotstuffResult<StateChanged>;
}

#[async_trait::async_trait]
pub trait LeaderProvider<B: BlockT> {
    async fn get_leader(&self, view: ViewNumber, session_index: SessionIndex) -> ValidatorId;
    async fn get_leader_before_commit(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
    ) -> ValidatorId;
    async fn get_leader_with_backups(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
        backup_num: usize,
    ) -> (ValidatorId, Vec<ValidatorId>);
    async fn update_leader_election_state(&self, hash: B::Hash, number: NumberFor<B>);
}

#[async_trait::async_trait]
pub trait QcProvider<B: BlockT> {
    async fn get_qc_of_block(&self, hash: &B::Hash) -> Option<QC<B>>;
}

// Worker messages and service handles

pub(crate) enum ServicetoWorkerMsg<B: BlockT> {
    CurView(oneshot::Sender<ViewNumber>),
    HighQC(oneshot::Sender<QC<B>>),
    HighTC(oneshot::Sender<TC<B>>),
    AdvanceView(
        Option<Box<QC<B>>>,
        Option<Box<TC<B>>>,
        oneshot::Sender<HotstuffResult<StateChanged>>,
    ),

    GetLeader(ViewNumber, SessionIndex, oneshot::Sender<ValidatorId>),
    GetLeaderBeforeCommit(ViewNumber, SessionIndex, oneshot::Sender<ValidatorId>),
    GetLeaderWithBackups(
        ViewNumber,
        SessionIndex,
        usize,
        oneshot::Sender<(ValidatorId, Vec<ValidatorId>)>,
    ),
    UpdateLeaderElectionState(B::Hash, NumberFor<B>),

    GetQcOfBlock(B::Hash, oneshot::Sender<Option<QC<B>>>),
}

pub struct StateWorker<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + AuxStore,
    C: HotstuffClient<B, BE>,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    from_service: mpsc::Receiver<ServicetoWorkerMsg<B>>,
    inner: HotstuffState<B, BE, C>,
}

#[derive(Clone, Debug)]
pub struct StateService<B: BlockT> {
    to_worker: mpsc::Sender<ServicetoWorkerMsg<B>>,
}

#[async_trait::async_trait]
impl<B: BlockT> ConsensusProvider<B> for StateService<B> {
    async fn cur_view(&self) -> ViewNumber {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::CurView(tx))
            .await
            .ok();

        rx.await.unwrap_or(GENESIS_VIEW)
    }

    async fn high_qc(&self) -> QC<B> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::HighQC(tx))
            .await
            .ok();

        rx.await.unwrap_or_default()
    }

    async fn high_tc(&self) -> TC<B> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::HighTC(tx))
            .await
            .ok();

        rx.await.unwrap_or_default()
    }

    async fn advance_view(
        &self,
        qc: Option<&QC<B>>,
        tc: Option<&TC<B>>,
    ) -> HotstuffResult<StateChanged> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::AdvanceView(
                qc.map(|x| Box::new(x.clone())),
                tc.map(|x| Box::new(x.clone())),
                tx,
            ))
            .await
            .ok();

        rx.await.unwrap_or(Ok(StateChanged::NotHappen))
    }
}

#[async_trait::async_trait]
impl<B: BlockT> LeaderProvider<B> for StateService<B> {
    async fn get_leader(&self, view: ViewNumber, session_index: SessionIndex) -> ValidatorId {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetLeader(view, session_index, tx))
            .await
            .ok();

        rx.await.unwrap_or_else(|_| default_validator_id())
    }

    async fn get_leader_before_commit(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
    ) -> ValidatorId {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetLeaderBeforeCommit(
                view,
                session_index,
                tx,
            ))
            .await
            .ok();

        rx.await.unwrap_or_else(|_| default_validator_id())
    }

    async fn get_leader_with_backups(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
        backup_num: usize,
    ) -> (ValidatorId, Vec<ValidatorId>) {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetLeaderWithBackups(
                view,
                session_index,
                backup_num,
                tx,
            ))
            .await
            .ok();

        rx.await
            .unwrap_or_else(|_| (default_validator_id(), vec![]))
    }

    async fn update_leader_election_state(&self, hash: B::Hash, number: NumberFor<B>) {
        let _ = self
            .to_worker
            .send(ServicetoWorkerMsg::UpdateLeaderElectionState(hash, number))
            .await;
    }
}

#[async_trait::async_trait]
impl<B: BlockT> QcProvider<B> for StateService<B> {
    async fn get_qc_of_block(&self, hash: &B::Hash) -> Option<QC<B>> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetQcOfBlock(*hash, tx))
            .await
            .ok();

        rx.await.ok().flatten()
    }
}

// State worker

impl<B, BE, C> StateWorker<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + AuxStore,
    C: HotstuffClient<B, BE>,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    pub fn new_with_service(
        client: Arc<C>,
        backend: Arc<BE>,
        session_info_service: Arc<SessionInfoService<B>>,
    ) -> (Self, StateService<B>) {
        let (to_worker, from_service) = mpsc::channel(1);
        let worker = Self {
            from_service,
            inner: HotstuffState::new(client, backend, session_info_service),
        };

        let service = StateService { to_worker };
        (worker, service)
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.from_service.recv() => match msg {
                    ServicetoWorkerMsg::CurView(sender) => {
                        let _ = sender.send(self.inner.cur_view);
                    },
                    ServicetoWorkerMsg::HighQC(sender) => {
                        let _ = sender.send(self.inner.high_qc.clone());
                    },
                    ServicetoWorkerMsg::HighTC(sender) => {
                        let _ = sender.send(self.inner.high_tc.clone());
                    },
                    ServicetoWorkerMsg::AdvanceView(qc, tc, sender) => {
                        let ret = self.inner.advance_view(qc.as_deref(), tc.as_deref());
                        let _ = sender.send(ret);
                    },
                    ServicetoWorkerMsg::GetLeader(view, session_index, sender) => {
                        let leader_id = self.inner.get_leader(view, session_index).await;
                        let _ = sender.send(leader_id);
                    },
                    ServicetoWorkerMsg::GetLeaderBeforeCommit(view, session_index, sender) => {
                        let leader_id = self.inner.get_leader_before_commit(view, session_index).await;
                        let _ = sender.send(leader_id);
                    },
                    ServicetoWorkerMsg::GetLeaderWithBackups(view, session_index, backup_num, sender) => {
                        let (leader_id, backups) = self.inner.get_leader_with_backups(view, session_index, backup_num).await;
                        let _ = sender.send((leader_id, backups));
                    }
                    ServicetoWorkerMsg::UpdateLeaderElectionState(hash, number) => {
                        self.inner.update_leader_election_state(hash, number);
                    },
                    ServicetoWorkerMsg::GetQcOfBlock(hash, sender) => {
                        let qc = self.inner.get_qc_of_block(&hash);
                        let _ = sender.send(qc);
                    }
                },
            };
        }
    }
}

/// Consensus state owned by the serial state worker.
#[derive(Clone)]
pub(crate) struct HotstuffState<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + AuxStore,
    C: HotstuffClient<B, BE>,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    /// current view
    pub cur_view: ViewNumber,
    /// highest qc for local authority
    pub high_qc: QC<B>,
    /// highest tc for local authority
    pub high_tc: TC<B>,
    /// latest committed block
    pub latest_committed_block_hash: B::Hash,
    pub prev_committed_block_hash: B::Hash,
    pub latest_committed_block_number: NumberFor<B>,
    /// blockchain client
    pub client: Arc<C>,
    pub backend: Arc<BE>,
    /// authority provider
    pub session_info_service: Arc<SessionInfoService<B>>,
    /// phantom
    _phantom: PhantomData<BE>,
}

impl<B, BE, C> HotstuffState<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + AuxStore,
    C: HotstuffClient<B, BE>,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    pub fn new(
        client: Arc<C>,
        backend: Arc<BE>,
        session_info_service: Arc<SessionInfoService<B>>,
    ) -> Self {
        // Consensus state should be initialized by genesis state
        let default_agg_sig = AggregateSignature::default();
        // Strictly speaking, there is no TC for genesis view,
        // the qc for genesis will override it's power so it's fine
        let tc_for_genesis =
            TC::<B>::new(GENESIS_VIEW, GENESIS_SESSION_INDEX, default_agg_sig.clone());
        let genesis_number: NumberFor<B> = Zero::zero();
        let qc_for_genesis = QC::<B>::new(
            client.info().genesis_hash,
            genesis_number,
            GENESIS_VIEW,
            GENESIS_SESSION_INDEX,
            default_agg_sig,
        );

        let client_info = client.info();
        let latest_committed_block_hash = client_info.finalized_hash;
        let latest_committed_block_number = client_info.finalized_number;
        let prev_committed_block_hash = if latest_committed_block_hash == client_info.genesis_hash {
            client_info.genesis_hash
        } else {
            let hash = match client.header(latest_committed_block_hash) {
                Ok(Some(header)) => *header.parent_hash(),
                _ => client_info.genesis_hash,
            };
            hash
        };

        let mut state = Self {
            cur_view: GENESIS_VIEW + 1,
            high_qc: qc_for_genesis.clone(),
            high_tc: tc_for_genesis.clone(),
            latest_committed_block_hash,
            prev_committed_block_hash,
            latest_committed_block_number,
            client,
            backend,
            session_info_service,
            _phantom: PhantomData,
        };

        let _ = state.load_high_tc();
        state
    }

    /// Advance view by sync info
    /// a newer QC or TC can change the cur view number
    /// QC and TC should have been verified before passing into this function
    pub fn advance_view(
        &mut self,
        qc: Option<&QC<B>>,
        tc: Option<&TC<B>>,
    ) -> HotstuffResult<StateChanged> {
        if qc.is_none() && tc.is_none() {
            return Ok(StateChanged::NotHappen);
        }

        let mut qc_updated = false;
        let mut tc_updated = false;

        if let Some(qc) = qc {
            qc_updated = self.update_high_qc(qc.clone());
        }

        if let Some(tc) = tc {
            tc_updated = self.update_high_tc(tc.clone());
        }

        let new_view = self.high_qc.view.max(self.high_tc.view) + 1;
        if new_view <= self.cur_view {
            return Ok(StateChanged::NotHappen);
        }

        self.cur_view = new_view;

        // Determine path based on which certificate actually caused the view change
        // If QC is newer than TC, it's a happy path (block succeeded)
        // Otherwise it's an unhappy path (timeout occurred)
        match (qc_updated, tc_updated) {
            (true, false) => Ok(StateChanged::HappyViewChangeTo(self.cur_view)),
            (true, true) => {
                // Both updated: if QC view >= TC view, block succeeded (happy)
                // Otherwise timeout won (unhappy)
                if self.high_qc.view >= self.high_tc.view {
                    Ok(StateChanged::HappyViewChangeTo(self.cur_view))
                } else {
                    Ok(StateChanged::UnhappyViewChangeTo(self.cur_view))
                }
            }
            _ => Ok(StateChanged::UnhappyViewChangeTo(self.cur_view)),
        }
    }

    fn update_high_qc(&mut self, qc: QC<B>) -> bool {
        if self.high_qc.view < qc.view {
            self.high_qc = qc;
            return true;
        }

        false
    }

    fn save_high_tc(&self, tc: &TC<B>) -> HotstuffResult<()> {
        let encoded = tc.encode();
        AuxStore::insert_aux(self.backend.as_ref(), &[(HIGH_TC_KEY, &encoded[..])], &[])
            .map_err(|e| HotstuffError::Other(format!("Failed to save high TC: {}", e)))?;

        log::debug!(
            target: LOG_TARGET,
            "Save high TC for view {} to storage",
            tc.view,
        );
        Ok(())
    }

    fn load_high_tc(&mut self) -> Option<TC<B>> {
        let tc_opt = AuxStore::get_aux(self.backend.as_ref(), HIGH_TC_KEY)
            .ok()
            .flatten()
            .and_then(|bytes| TC::<B>::decode(&mut &bytes[..]).ok());
        let _ = self.advance_view(None, tc_opt.as_ref());
        tc_opt
    }

    fn update_high_tc(&mut self, tc: TC<B>) -> bool {
        if self.high_tc.view < tc.view {
            self.high_tc = tc.clone();
            if let Err(e) = self.save_high_tc(&tc) {
                log::error!(
                    target: LOG_TARGET,
                    "Failed to persist high TC: {:?}",
                    e
                );
            }
            return true;
        }

        false
    }

    /// Update latest committed block
    pub fn update_leader_election_state(&mut self, hash: B::Hash, number: NumberFor<B>) {
        if number <= self.latest_committed_block_number {
            return;
        }
        self.latest_committed_block_hash = hash;
        self.latest_committed_block_number = number;
        match self.client.header(hash) {
            Ok(Some(h)) => self.prev_committed_block_hash = *h.parent_hash(),
            Ok(None) => {}
            Err(_) => {}
        };
    }

    async fn get_leader_by_committed_hash(
        &self,
        latest_committed_hash: B::Hash,
        view: ViewNumber,
        session_index: SessionIndex,
        backup_num: usize,
    ) -> (AccountId, Vec<AccountId>) {
        use crate::crypto::QuorumSignature;

        let fallback_leader = async |v| {
            let Some(authorities) = self.session_info_service.authorities(session_index).await
            else {
                log::error!(target: LOG_TARGET, "Missing authorities for leader election");
                return (default_validator_id(), vec![]);
            };
            shuffle_and_select_leader(authorities.keys().cloned().collect(), v, backup_num)
        };

        // Genesis has no QC signers. Vary the candidate with the view so an offline
        // first authority cannot prevent a live quorum from starting the chain.
        if self.client.info().genesis_hash == latest_committed_hash {
            return fallback_leader(view).await;
        }

        let leader_for_session_boundary =
            async |new_session_index: SessionIndex, preferred_signers: Vec<ValidatorId>| {
                // If we are at a session boundary, we may encounter the following issue:
                // The current session is 3, but the QC belongs to session 2. In this case,
                // the participants recorded in the QC may no longer be validators in session 3.
                //
                // Clearly, we should avoid selecting an authority that is no longer part of the
                // current validator set. We should also avoid picking a *new* authority because
                // it may miss vote messages while network connections are still being established.
                //
                // Therefore, we choose an authority from the intersection of the two sets
                // (currently we simply select the first intersecting validator).
                log::debug!(
                    target: LOG_TARGET,
                    "[GET LEADER] session boundary {}", new_session_index,
                );
                let Some(new_authorities) = self
                    .session_info_service
                    .authorities(new_session_index)
                    .await
                else {
                    log::error!(target: LOG_TARGET, "Failed to get new authorities for session boundary, using default");
                    return (default_validator_id(), vec![]);
                };
                let Some(prev_authorities) = self
                    .session_info_service
                    // Catch-up may request session 0 with a newer committed QC.
                    // Genesis has no previous session; never wrap to u32::MAX.
                    .authorities(new_session_index.saturating_sub(1))
                    .await
                else {
                    log::error!(target: LOG_TARGET, "Failed to get prev authorities for session boundary, using new session first");
                    let mut keys_iter = new_authorities.keys();
                    let first = keys_iter
                        .next()
                        .cloned()
                        .unwrap_or_else(default_validator_id);
                    let backups: Vec<AccountId> = keys_iter.take(backup_num).cloned().collect();
                    return (first, backups);
                };

                log::trace!(target: LOG_TARGET, "new_authorities: {:?} prev_authorities: {:?}", new_authorities, prev_authorities);
                let intersection: Vec<ValidatorId> = new_authorities
                    .keys()
                    .filter(|k| prev_authorities.contains_key(*k))
                    .cloned()
                    .collect();

                let candidates =
                    session_boundary_candidates(intersection, preferred_signers, backup_num);

                shuffle_and_select_leader(candidates, view, backup_num)
            };

        // since the block has been committed, there must be a locked qc
        match self.get_qc_of_block(&latest_committed_hash) {
            Some(qc_for_committed) => {
                if !qc_for_committed.agg_sig.is_valid() {
                    return fallback_leader(view).await;
                }

                // First 2 blocks of a new session use a different leader selecting strategy
                // to avoid a new-joined validator becoming the leader
                // as it might delay for connecting
                if qc_for_committed.session_index != session_index {
                    let new_session_mapping = self
                        .session_info_service
                        .get_validator_ids(session_index)
                        .await;
                    let preferred_signers = qc_for_committed
                        .agg_sig
                        .participants()
                        .to_validator_ids(&new_session_mapping);
                    return leader_for_session_boundary(session_index, preferred_signers).await;
                }

                let candidates = qc_for_committed.agg_sig.participants();
                let mapping = self
                    .session_info_service
                    .get_validator_ids(session_index)
                    .await;
                let validator_ids = candidates.to_validator_ids(&mapping);
                if validator_ids.is_empty() {
                    log::warn!(
                        target: LOG_TARGET,
                        "[GET LEADER] no participants in QC, fallback to the authority set"
                    );
                    return fallback_leader(view).await;
                }

                if validator_ids.len() < (1 + backup_num) {
                    log::warn!(
                        target: LOG_TARGET,
                        "[GET LEADER] not enough candidates ({} < {}), fallback to the authority set",
                        validator_ids.len(), 1 + backup_num
                    );
                    return fallback_leader(view).await;
                }

                let (leader, backups) =
                    shuffle_and_select_leader(validator_ids.clone(), view, backup_num);

                log::trace!(
                    target: LOG_TARGET,
                    "[GET LEADER] Selected leader: {:?}, backups: {:?}",
                    leader,
                    backups
                );

                (leader, backups)
            }
            None => {
                log::warn!(
                    target: LOG_TARGET,
                    "[GET LEADER] No QC found for committed block: {:?}, fallback to the authority set",
                    latest_committed_hash,
                );
                fallback_leader(view).await
            }
        }
    }

    fn get_qc_of_block(&self, hash: &B::Hash) -> Option<QC<B>> {
        let justs = self.backend.blockchain().justifications(*hash).ok()??;

        QC::<B>::from_justifications(justs)
    }
}

impl<B, BE, C> HotstuffState<B, BE, C>
where
    B: BlockT,
    BE: Backend<B> + AuxStore,
    C: HotstuffClient<B, BE>,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    async fn get_leader(&self, view: ViewNumber, session_index: SessionIndex) -> ValidatorId {
        let latest_committed_hash = self.latest_committed_block_hash;
        self.get_leader_by_committed_hash(latest_committed_hash, view, session_index, 0)
            .await
            .0
    }

    async fn get_leader_before_commit(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
    ) -> ValidatorId {
        let latest_committed_hash = self.prev_committed_block_hash;
        self.get_leader_by_committed_hash(latest_committed_hash, view, session_index, 0)
            .await
            .0
    }

    pub async fn get_leader_with_backups(
        &self,
        view: ViewNumber,
        session_index: SessionIndex,
        backup_num: usize,
    ) -> (ValidatorId, Vec<ValidatorId>) {
        let latest_committed_hash = self.latest_committed_block_hash;
        self.get_leader_by_committed_hash(latest_committed_hash, view, session_index, backup_num)
            .await
    }
}

/// StateChanged leads to different actions of Core
pub enum StateChanged {
    /// view change by happy path
    HappyViewChangeTo(ViewNumber),
    /// view change by unhappy path
    UnhappyViewChangeTo(ViewNumber),
    /// view change does not happen
    NotHappen,
}

#[cfg(test)]
#[path = "../unit_tests/state.rs"]
mod tests;
