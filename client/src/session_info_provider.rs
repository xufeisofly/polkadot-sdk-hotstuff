use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
    sync::Arc,
};

use codec::Encode;
use sc_consensus_hotstuff_bls::PublicKey;
use sp_consensus_hotstuff::HotstuffApi;
use sp_consensus_hotstuff::{
    hash_of, AccountId, AuthorityDiscoveryId, AuthorityId, BlsPublicBytes, SessionIndex,
    HOTSTUFF_KEY_TYPE,
};

use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as ClientError, HeaderBackend};
use sp_core::U256;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};

use crate::aux_store;
use crate::primitives::{AuthorityInfo, AuthoritySet, ValidatorId, GENESIS_SESSION_INDEX};

const LOG_TARGET: &str = "sc-consensus-hotstuff::session-info";

pub(crate) fn quorum_voting_power_from_total(total_voting_power: usize) -> usize {
    (total_voting_power * 2).div_ceil(3)
}

/// First block signed by a session, within the chain's u32 block-number range.
fn first_block_of_session(session_index: SessionIndex, period: u32, offset: u32) -> Option<u32> {
    if session_index == GENESIS_SESSION_INDEX {
        return Some(0);
    }
    let first_block =
        U256::from(offset) + U256::from(session_index) * U256::from(period) + U256::one();
    first_block.try_into().ok()
}

/// Floor lookup over an already-loaded warp authority map: the authority set stored at the
/// greatest key `<= session_index`, or `None` if no stored key satisfies it. Thin wrapper over
/// [`aux_store::floor_lookup`] that reuses a decoded `Vec` (avoiding a re-read of the aux store);
/// the floor logic itself lives in one place in `aux_store`.
fn floor_lookup_warp_map(
    map: &[(SessionIndex, Vec<AuthorityInfo>)],
    session_index: SessionIndex,
) -> Option<Vec<AuthorityInfo>> {
    aux_store::floor_lookup(map, session_index)
}

/// Retry interval for failed session refresh attempts (in seconds)
const REFRESH_RETRY_INTERVAL_SECS: u64 = 2;

/// Bounded wait for the worker to answer an authorities query, so a stuck-alive worker cannot hang
/// the caller indefinitely. A dead worker already resolves immediately (dropped sender).
const GET_AUTHORITIES_TIMEOUT: Duration = Duration::from_secs(5);

/// Entry in the retry queue for failed refresh attempts
#[derive(Debug, Clone)]
struct RefreshRetryEntry {
    /// The session index that was expected after refresh
    expected_session_index: SessionIndex,
    /// Time when this entry was added to the queue
    enqueued_at: Instant,
    /// Number of retry attempts made
    retry_count: usize,
}

/// Provide authority infos of a session
#[async_trait::async_trait]
pub trait SessionAuthorityProvider<B: BlockT> {
    async fn is_authoritiy_for_current_session(&self) -> bool;
    async fn current_session_index(&self) -> SessionIndex;
    async fn historical_session_index(&self) -> SessionIndex;
    // all the authorities of the session
    async fn authorities(&self, session_index: SessionIndex) -> Option<AuthoritySet>;
    async fn validator_ids_hash(&self, new_session_index: SessionIndex) -> B::Hash;
    // local authority id of the session
    async fn local_authority_id(&self, session_index: SessionIndex) -> Option<AuthorityId>;
    // get authority id of the session
    async fn get_authority_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<AuthorityId>;
    // local authority_discovery_id of the session
    async fn local_auth_disc_id(&self, session_index: SessionIndex)
        -> Option<AuthorityDiscoveryId>;
    // get authority_discovery_id of the session
    async fn get_auth_disc_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<AuthorityDiscoveryId>;
    async fn get_bls_public(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<PublicKey>;
    async fn local_validator_id(&self) -> Option<ValidatorId>;
    // voting info
    async fn total_voting_power(&self, session_index: SessionIndex) -> usize;
    async fn quorum_voting_power(&self, session_index: SessionIndex) -> usize;
    async fn advance_current_session(&self) -> SessionIndex;
    async fn advance_historical_session(&self, block_number: NumberFor<B>) -> SessionIndex;
    async fn session_index_by_number(&self, block_number: NumberFor<B>) -> SessionIndex;
    // validator ids is ordered, can be used as a mapping from index to validator id
    async fn get_validator_ids(&self, session_index: SessionIndex) -> Arc<Vec<ValidatorId>>;
    /// Check if session should end at the given block number using runtime API.
    /// Returns true if the block is the last block of current session.
    async fn should_end_session(&self, block_number: NumberFor<B>) -> bool;
    /// Check if session should end at the given block number using manual calculation.
    /// Returns true if the block is the last block of current session based on offset and period.
    async fn should_end_session_by_calculation(&self, block_number: NumberFor<B>) -> bool;
    /// Check if the given block number is the first block of a session.
    /// Returns true if the previous block was the last block of a session.
    async fn is_first_block_of_session(&self, block_number: NumberFor<B>) -> bool;
    /// Check if the given block number belongs to the specified session.
    /// Returns true if block_number is within the session's range.
    async fn is_number_match_session(
        &self,
        block_number: NumberFor<B>,
        session_index: SessionIndex,
    ) -> bool;
}

pub(crate) enum ServicetoWorkerMsg<B: BlockT> {
    IsAuthorityForCurrentSession(oneshot::Sender<bool>),
    CurrentSessionIndex(oneshot::Sender<SessionIndex>),
    HistoricalSessionIndex(oneshot::Sender<SessionIndex>),
    GetAuthorities(SessionIndex, oneshot::Sender<Option<AuthoritySet>>),
    ValidatorIdsHash(SessionIndex, oneshot::Sender<B::Hash>),
    LocalAuthorityId(SessionIndex, oneshot::Sender<Option<AuthorityId>>),
    GetAuthorityId(
        SessionIndex,
        ValidatorId,
        oneshot::Sender<Option<AuthorityId>>,
    ),
    LocalAuthDiscId(SessionIndex, oneshot::Sender<Option<AuthorityDiscoveryId>>),
    GetAuthDiscId(
        SessionIndex,
        ValidatorId,
        oneshot::Sender<Option<AuthorityDiscoveryId>>,
    ),
    LocalValidatorId(oneshot::Sender<Option<ValidatorId>>),
    GetBlsPublc(
        SessionIndex,
        ValidatorId,
        oneshot::Sender<Option<PublicKey>>,
    ),

    TotalVotingPower(SessionIndex, oneshot::Sender<usize>),
    QuorumVotingPower(SessionIndex, oneshot::Sender<usize>),
    // advance current (best) session timeline
    AdvanceCurrentSession(oneshot::Sender<SessionIndex>),
    // advance historical session timeline using historical_authority_set
    AdvanceHistoricalSession(NumberFor<B>, oneshot::Sender<SessionIndex>),
    // calculate session index by block number using local session config
    SessionIndexByNumber(NumberFor<B>, oneshot::Sender<SessionIndex>),
    GetValidatorIds(SessionIndex, oneshot::Sender<Arc<Vec<ValidatorId>>>),
    ShouldEndSession(NumberFor<B>, oneshot::Sender<bool>),
}

pub struct SessionInfoWorker<B, C>
where
    B: BlockT,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + sc_client_api::AuxStore,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    period: u32,
    offset: u32,
    from_service: mpsc::Receiver<ServicetoWorkerMsg<B>>,
    // from pallet hotstuff
    cur_session_index: SessionIndex,
    // The session `prev_authority_set` actually holds (the previous refresh's cur). Equals
    // `cur_session_index - 1` only under sequential advancement; a warp-sync node jumps sessions,
    // so matching this stored index avoids returning a stale `prev` set for a session never visited.
    prev_session_index: SessionIndex,
    // We have prev authority set to deal with the session boundary problem
    prev_authority_set: AuthoritySet,
    cur_authority_set: AuthoritySet,
    next_authority_set: AuthoritySet,
    // Cache for historical session authority set to avoid repeated runtime API queries
    historical_authority_set: Option<(SessionIndex, AuthoritySet)>,
    client: Arc<C>,
    keystore: KeystorePtr,
    local_validator_id: Option<ValidatorId>,
    is_authority_for_cur: bool,
    // Retry queue for failed session refresh attempts
    retry_queue: VecDeque<RefreshRetryEntry>,
    // Timer for the next retry attempt
    next_retry_time: Option<Instant>,
    _phantom: PhantomData<B>,
}

#[derive(Clone, Debug)]
pub struct SessionInfoService<B: BlockT> {
    period: u32,
    offset: u32,
    to_worker: mpsc::Sender<ServicetoWorkerMsg<B>>,
}

impl<B: BlockT> SessionInfoService<B> {
    #[cfg(test)]
    pub(crate) fn new_for_test(sender: mpsc::Sender<ServicetoWorkerMsg<B>>) -> Self {
        Self {
            to_worker: sender,
            period: 100,
            offset: 0,
        }
    }
}

impl<B, C> SessionInfoWorker<B, C>
where
    B: BlockT,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + sc_client_api::AuxStore,
    C::Api: HotstuffApi<B, NumberFor<B>>,
{
    pub fn new_with_service(
        client: Arc<C>,
        keystore: KeystorePtr,
    ) -> Result<(Self, SessionInfoService<B>), ClientError> {
        let (period, offset) = client
            .runtime_api()
            .session_schedule(client.info().best_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;
        if period == 0 || offset != 0 {
            return Err(ClientError::Backend(
                "Hotstuff requires a nonzero session period and zero offset".into(),
            ));
        }
        let (to_worker, from_service) = mpsc::channel(1);
        let mut worker = Self {
            period,
            offset,
            from_service,
            cur_session_index: GENESIS_SESSION_INDEX,
            prev_session_index: GENESIS_SESSION_INDEX,
            prev_authority_set: BTreeMap::new(),
            cur_authority_set: BTreeMap::new(),
            next_authority_set: BTreeMap::new(),
            historical_authority_set: None,
            client,
            keystore,
            local_validator_id: None,
            is_authority_for_cur: false,
            retry_queue: VecDeque::new(),
            next_retry_time: None,
            _phantom: Default::default(),
        };

        worker.refresh()?;

        let service = SessionInfoService {
            to_worker,
            period,
            offset,
        };
        Ok((worker, service))
    }

    pub async fn run(mut self) {
        let mut retry_interval =
            tokio::time::interval(Duration::from_secs(REFRESH_RETRY_INTERVAL_SECS));
        retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(msg) = self.from_service.recv() => match msg {
                    ServicetoWorkerMsg::IsAuthorityForCurrentSession(sender) => self.handle_is_authority_for_cur(sender),
                    ServicetoWorkerMsg::CurrentSessionIndex(sender) => self.handle_current_session_index(sender),
                    ServicetoWorkerMsg::HistoricalSessionIndex(sender) => self.handle_historical_session_index(sender),
                    ServicetoWorkerMsg::AdvanceCurrentSession(sender) => self.handle_new_session(sender),
                    ServicetoWorkerMsg::AdvanceHistoricalSession(block_number, sender) => self.handle_advance_historical_session(block_number, sender),
                    ServicetoWorkerMsg::SessionIndexByNumber(block_number, sender) => self.handle_session_index_by_number(block_number, sender),
                    ServicetoWorkerMsg::GetAuthorities(session_index, sender) => self.handle_get_authorities(session_index, sender),
                    ServicetoWorkerMsg::LocalAuthorityId(session_index, sender) => self.handle_local_authority_id(session_index, sender),
                    ServicetoWorkerMsg::GetAuthorityId(session_index, id, sender) => self.handle_get_authority_id(session_index, &id, sender),
                    ServicetoWorkerMsg::ValidatorIdsHash(session_index, sender) => self.handle_validator_ids_hash(session_index, sender),
                    ServicetoWorkerMsg::LocalAuthDiscId(session_index, sender) => self.handle_local_auth_disc_id(session_index, sender),
                    ServicetoWorkerMsg::GetAuthDiscId(session_index, id, sender) => self.handle_get_auth_disc_id(session_index, &id, sender),
                    ServicetoWorkerMsg::LocalValidatorId(sender) => self.handle_local_validator_id(sender),
                    ServicetoWorkerMsg::GetBlsPublc(session_index, id, sender) => self.handle_get_bls_public(session_index, &id, sender),
                    ServicetoWorkerMsg::TotalVotingPower(session_index, sender) => self.handle_total_voting_power(session_index, sender),
                    ServicetoWorkerMsg::QuorumVotingPower(session_index, sender) => self.handle_quorum_voting_power(session_index, sender),
                    ServicetoWorkerMsg::GetValidatorIds(session_index, sender) => self.handle_get_validator_ids(session_index, sender),
                    ServicetoWorkerMsg::ShouldEndSession(block_number, sender) => self.handle_should_end_session(block_number, sender),
                },
                _ = retry_interval.tick() => {
                    self.process_retry_queue();
                }
            };
        }
    }

    // Current-session refresh and retries

    pub fn refresh(&mut self) -> Result<(), ClientError> {
        let best_hash = self.client.info().best_hash;

        let authorities = self
            .client
            .runtime_api()
            .authorities(best_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;

        let new_local_validator_id = {
            let r = Self::to_authority_set(authorities.clone());
            r.iter()
                .find(|(_, info)| {
                    let key_bytes = <AuthorityId as AsRef<[u8]>>::as_ref(&info.1).to_vec();
                    self.keystore.has_keys(&[(key_bytes, HOTSTUFF_KEY_TYPE)])
                })
                .map(|(id, _)| id.clone())
        };

        let new_is_authority = new_local_validator_id.is_some();

        log::debug!(
            target: LOG_TARGET,
            "local validator id: {:?}",
            new_local_validator_id
        );

        // If local_validator_id is none, it means that validator is not in current session authorities,
        // however, we should not clear local_validator_id as it's a common property of any nodes, not only for authorities,
        // but it's AuthorityInfo of this session should be None

        // for genesis
        if best_hash == self.client.info().genesis_hash {
            self.local_validator_id = new_local_validator_id;
            self.is_authority_for_cur = new_is_authority;
            self.cur_authority_set = Self::to_authority_set(authorities.clone());
            self.next_authority_set = Self::to_authority_set(authorities);
            return Ok(());
        }

        let current_session_index = self
            .client
            .runtime_api()
            .current_session_index(best_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;

        let next_authorities = self
            .client
            .runtime_api()
            .next_authorities(best_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;

        self.local_validator_id = new_local_validator_id;
        self.is_authority_for_cur = new_is_authority;
        // Record the session prev now holds (old cur) before overwriting cur_session_index.
        self.prev_session_index = self.cur_session_index;
        self.prev_authority_set = self.cur_authority_set.clone();
        self.cur_authority_set = Self::to_authority_set(authorities);
        self.next_authority_set = Self::to_authority_set(next_authorities);
        self.cur_session_index = current_session_index;

        log::debug!(
            target: LOG_TARGET,
            "Refreshed session info at #{:?}. Index: {}, Is Auth: {}",
            best_hash,
            current_session_index,
            new_is_authority
        );

        Ok(())
    }

    pub fn on_session_rotate(&mut self) -> bool {
        let old_session_index = self.cur_session_index;

        // Clear previous retry queue when new session rotate is triggered
        if !self.retry_queue.is_empty() {
            log::info!(
                target: LOG_TARGET,
                "Clearing {} pending retry entries due to new session rotate",
                self.retry_queue.len()
            );
            self.retry_queue.clear();
            self.next_retry_time = None;
        }

        match self.refresh() {
            Ok(()) => {
                log::info!(
                    target: LOG_TARGET,
                    "on_session_rotate completed successfully, session: {} -> {}",
                    old_session_index,
                    self.cur_session_index
                );
                true
            }
            Err(_) => {
                log::error!(
                    target: LOG_TARGET,
                    "on_session_rotate failed after retries, enqueuing retry for session {}",
                    old_session_index + 1
                );
                self.enqueue_retry(old_session_index + 1);
                false
            }
        }
    }

    /// Enqueue a failed refresh attempt for retry
    fn enqueue_retry(&mut self, expected_session_index: SessionIndex) {
        let entry = RefreshRetryEntry {
            expected_session_index,
            enqueued_at: Instant::now(),
            retry_count: 0,
        };
        self.retry_queue.push_back(entry);

        // Set next retry time if not already set
        if self.next_retry_time.is_none() {
            self.next_retry_time =
                Some(Instant::now() + Duration::from_secs(REFRESH_RETRY_INTERVAL_SECS));
        }

        log::debug!(
            target: LOG_TARGET,
            "Enqueued retry for session {}, queue size: {}",
            expected_session_index,
            self.retry_queue.len()
        );
    }

    /// Process retry queue and attempt to refresh for failed entries
    fn process_retry_queue(&mut self) {
        if self.retry_queue.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut entries_to_retry = Vec::new();

        // Collect entries that are due for retry
        while let Some(entry) = self.retry_queue.pop_front() {
            if now.duration_since(entry.enqueued_at)
                >= Duration::from_secs(REFRESH_RETRY_INTERVAL_SECS * (entry.retry_count as u64 + 1))
            {
                entries_to_retry.push(entry);
            } else {
                // Put it back if not due yet
                self.retry_queue.push_front(entry);
                break;
            }
        }

        // Process each entry
        for mut entry in entries_to_retry {
            entry.retry_count += 1;

            log::info!(
                target: LOG_TARGET,
                "Retrying session refresh for session {} (attempt #{})",
                entry.expected_session_index,
                entry.retry_count
            );

            match self.refresh() {
                Ok(()) => {
                    log::info!(
                        target: LOG_TARGET,
                        "Retry successful: session index updated to {} after {} attempts",
                        self.cur_session_index,
                        entry.retry_count
                    );
                }
                Err(e) => {
                    log::warn!(
                        target: LOG_TARGET,
                        "Retry failed for session {} (attempt {}): {}, re-enqueueing",
                        entry.expected_session_index,
                        entry.retry_count,
                        e
                    );
                    // Re-enqueue for another retry
                    self.retry_queue.push_back(entry);
                }
            }
        }

        log::debug!(
            target: LOG_TARGET,
            "Retry queue processed, {} entries remaining",
            self.retry_queue.len()
        );
    }

    // Session queries and historical rotation

    fn handle_is_authority_for_cur(&self, sender: oneshot::Sender<bool>) {
        let _ = sender.send(self.is_authority_for_cur);
    }

    fn handle_current_session_index(&self, sender: oneshot::Sender<SessionIndex>) {
        let _ = sender.send(self.cur_session_index);
    }

    fn handle_historical_session_index(&self, sender: oneshot::Sender<SessionIndex>) {
        let historical_session_index = self
            .historical_authority_set
            .as_ref()
            .map(|(idx, _)| *idx)
            .unwrap_or(GENESIS_SESSION_INDEX);
        let _ = sender.send(historical_session_index);
    }

    fn handle_new_session(&mut self, sender: oneshot::Sender<SessionIndex>) {
        let _ = self.on_session_rotate();
        let _ = sender.send(self.cur_session_index);
    }

    fn handle_advance_historical_session(
        &mut self,
        block_number: NumberFor<B>,
        sender: oneshot::Sender<SessionIndex>,
    ) {
        match self.on_historical_session_rotate(block_number) {
            Ok(_) => log::info!(
                target: LOG_TARGET,
                "Historical session advanced successfully at block #{}",
                block_number
            ),
            Err(e) => log::error!(
                target: LOG_TARGET,
                "Failed to advance historical session at block #{}: {}",
                block_number,
                e
            ),
        }
        let old_session_index = self
            .historical_authority_set
            .as_ref()
            .map(|(idx, _)| *idx)
            .unwrap_or(0);
        let _ = sender.send(old_session_index);
    }

    fn handle_session_index_by_number(
        &self,
        block_number: NumberFor<B>,
        sender: oneshot::Sender<SessionIndex>,
    ) {
        let session_index = self.current_session_index_by_number(block_number);
        let _ = sender.send(session_index);
    }

    /// Calculate session index for a block number using PeriodicSessions rule.
    fn current_session_index_by_number(&self, block_number: NumberFor<B>) -> SessionIndex {
        let number: U256 = block_number.into();
        let offset: U256 = U256::from(self.offset);
        let period: U256 = U256::from(self.period);

        if number < offset {
            return GENESIS_SESSION_INDEX;
        }

        let delta = number - offset;
        let quotient = delta / period;
        let is_boundary = !delta.is_zero() && (delta % period).is_zero();

        let session = if is_boundary {
            quotient.saturating_sub(U256::one())
        } else {
            quotient
        };

        session.as_u32()
    }

    /// Advance the historical session timeline for an old block and update historical_authority_set.
    fn on_historical_session_rotate(
        &mut self,
        block_number: NumberFor<B>,
    ) -> Result<(), ClientError> {
        let Some(block_hash) = self
            .client
            .hash(block_number)
            .map_err(|e| ClientError::Execution(Box::new(e)))?
        else {
            log::warn!(
                target: LOG_TARGET,
                "Block hash not found for historical block #{:?}",
                block_number
            );
            return Err(ClientError::Backend(format!(
                "Block hash not found for block #{}",
                block_number
            )));
        };

        log::debug!(
            target: LOG_TARGET,
            "===2 Querying historical session index for block #{} ({:?})",
            block_number,
            block_hash
        );

        let runtime_api = self.client.runtime_api();
        let session_index = runtime_api
            .current_session_index(block_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;

        let authorities = runtime_api
            .authorities(block_hash)
            .map_err(|e| ClientError::Execution(Box::new(e)))?;

        let authority_set = Self::to_authority_set(authorities);
        self.historical_authority_set = Some((session_index, authority_set));

        log::debug!(
            target: LOG_TARGET,
            "Historical session timeline advanced at block #{:?} ({:?}) -> session {}",
            block_number,
            block_hash,
            session_index
        );

        Ok(())
    }

    fn handle_should_end_session(&self, block_number: NumberFor<B>, sender: oneshot::Sender<bool>) {
        let at = self.client.info().best_hash;
        let should_end = self
            .client
            .runtime_api()
            .should_end_session(at, block_number)
            .unwrap_or(false);
        let _ = sender.send(should_end);
    }

    // Authority-set lookup and caching

    /// Resolves authorities from the live cache, then historical cache, warp map or runtime API.
    fn handle_get_authorities(
        &mut self,
        session_index: SessionIndex,
        sender: oneshot::Sender<Option<AuthoritySet>>,
    ) {
        // Live cur/prev/next cache first (current consensus, in-memory), then the historical path
        // (warp map for warp-covered sessions, then runtime API). Safe on warp nodes because the
        // live cache answers only for sessions it actually holds, so a pruned historical session
        // falls through to the boundary-correct warp map.
        let authority_set = if let Some(set) = self.try_get_authority_set_from_new(session_index) {
            Some(set.clone())
        } else {
            self.try_get_authority_set_from_historical(session_index)
        };

        if authority_set.is_none() {
            log::warn!(
                target: LOG_TARGET,
                "Failed to get authority set for session {} from neither new nor old cache",
                session_index
            );
        }

        let _ = sender.send(authority_set);
    }

    /// Try to get authority set for the specified session from new cached sets.
    fn try_get_authority_set_from_new(&self, session_index: SessionIndex) -> Option<&AuthoritySet> {
        // Match `prev` against the session it actually holds (`prev_session_index`), not the
        // arithmetic `cur - 1`, so a warp-sync node (which jumps sessions) doesn't return a stale
        // `prev` set. Identical to `cur - 1` under sequential advancement.
        if session_index == self.cur_session_index {
            Some(&self.cur_authority_set)
        } else if session_index == self.prev_session_index {
            Some(&self.prev_authority_set)
        } else if session_index == self.cur_session_index.saturating_add(1) {
            Some(&self.next_authority_set)
        } else {
            None
        }
    }

    /// Try to get authority set from old cache or query historical authorities.
    /// The historical_authority_set is mainly for gap blocks syncing in Warp Sync mode.
    fn try_get_authority_set_from_historical(
        &mut self,
        session_index: SessionIndex,
    ) -> Option<AuthoritySet> {
        if let Some((cached_session, cached_set)) = &self.historical_authority_set {
            // Check if we have this historical session cached
            if *cached_session == session_index {
                log::debug!(
                    target: LOG_TARGET,
                    "Using cached historical_authority_set for session {}",
                    session_index
                );
                return Some(cached_set.clone());
            }
        }

        // For historical sessions, we need to query from runtime API
        // Since this method returns a reference, we cannot store the result here
        // Callers should use the async `authorities()` method from SessionInfoService instead
        log::trace!(
            target: LOG_TARGET,
            "Attempted to get authority set from cache for historical session {} (current: {}), returning None. Use async authorities() method instead.",
            session_index,
            self.cur_session_index
        );

        // Different historical session or no cache yet, query and update cache
        self.query_and_cache_historical_authorities(session_index)
    }

    /// Query historical session authorities and update the single-entry cache.
    ///
    /// Resolution order:
    ///
    /// (A) Warp map (authoritative, NO state required) for any session that is `<= max_map_key`.
    /// The warp map (T03/T06) is keyed by `next_session_index` (the session each set first signs);
    /// a floor-lookup of `session_index` returns the set in effect at that session. The
    /// `<= max_map_key` guard is essential: above the highest recorded change a floor-hit would
    /// wrongly return a stale set for a post-warp/live session that the runtime API can still
    /// answer, so we only trust the map up to the highest warp-covered session change.
    ///
    /// (B) Runtime API at the last block of session N-1 (full-history nodes, or post-warp/live
    /// sessions whose state is still present). This is the original behaviour.
    ///
    /// (C) Last-resort floor-lookup over the warp map when the runtime API fails (e.g. a warp node
    /// for a session just above the last recorded change, where no state exists).
    ///
    /// Net effect: a full-history node has an empty warp map, so (A)/(C) are skipped and it behaves
    /// exactly as before (pure runtime-API path).
    fn query_and_cache_historical_authorities(
        &mut self,
        session_index: SessionIndex,
    ) -> Option<AuthoritySet> {
        // Load the warp authority map once and reuse it for the floor-lookups in (A) and (C),
        // avoiding a second decode of the aux store. Empty for full-history nodes.
        let warp_map = aux_store::load_warp_authority_map(self.client.as_ref()).unwrap_or_default();
        let max_map_key = warp_map.last().map(|(s, _)| *s);

        // The highest session this node warp-synced to, if any. At/below the warp point the
        // historical chain STATE has been pruned, so the runtime API cannot answer authority
        // queries there — the warp authority map is the only source, and it is authoritative.
        // We therefore route every session `<= warp_session` straight to the map and never touch
        // the runtime API for it (which would otherwise emit a scary "State already discarded"
        // warning on every gap-synced historical block before falling back to the map).
        let warp_session = aux_store::load_warp_sync_point::<B, _>(self.client.as_ref())
            .ok()
            .flatten()
            .map(|warp_number| self.current_session_index_by_number(warp_number));

        // (A) Resolve from the warp map when the session is within warp coverage: at/below the warp
        //     point (state pruned), or not beyond the last recorded change (`max_map_key`). These
        //     bounds prevent a stale floor-hit for post-warp/live sessions, which (B) answers from
        //     the runtime API. On a full-history node both bounds are absent, so (A) is skipped.
        let map_covers = warp_session.map(|ws| session_index <= ws).unwrap_or(false)
            || max_map_key.map(|mk| session_index <= mk).unwrap_or(false);
        if map_covers {
            if let Some(set) = floor_lookup_warp_map(&warp_map, session_index) {
                let authority_set = Self::to_authority_set(set);
                log::debug!(
                    target: LOG_TARGET,
                    "Resolved historical session {} from warp authority map (warp_session={:?}, max_key={:?})",
                    session_index,
                    warp_session,
                    max_map_key
                );
                self.historical_authority_set = Some((session_index, authority_set.clone()));
                return Some(authority_set);
            }
        }

        // (B) Not warp-covered (full-history node, or post-warp/live session with state available):
        //     query the runtime API. Query from the last block of previous session instead of the
        //     first block of the target session.
        // This avoids the issue where the first block of target session hasn't been imported yet
        // In Substrate, the authority set for session N is determined at the end of session N-1
        let query_block_number = if session_index == GENESIS_SESSION_INDEX {
            // For genesis session, use block 0
            NumberFor::<B>::from(0u32)
        } else {
            // For session N (N > 0), use the last block of session N-1
            // Last block of session N-1 = first block of session N - 1
            let first_block = NumberFor::<B>::from(first_block_of_session(
                session_index,
                self.period,
                self.offset,
            )?);
            first_block - NumberFor::<B>::from(1u32)
        };

        let runtime_result = match self.client.hash(query_block_number) {
            Ok(Some(block_hash)) => match self.client.runtime_api().authorities(block_hash) {
                Ok(old_authorities) => {
                    let authority_set = Self::to_authority_set(old_authorities);
                    log::debug!(
                        target: LOG_TARGET,
                        "Retrieved and cached authorities for historical session {} at block #{} ({:?})",
                        session_index,
                        query_block_number,
                        block_hash
                    );
                    // Update cache with new historical session
                    self.historical_authority_set = Some((session_index, authority_set.clone()));
                    Some(authority_set)
                }
                Err(e) => {
                    log::warn!(
                        target: LOG_TARGET,
                        "Failed to get authorities for session {} at block #{}: {}",
                        session_index,
                        query_block_number,
                        e
                    );
                    None
                }
            },
            Ok(None) => {
                log::warn!(
                    target: LOG_TARGET,
                    "Block hash not found for session {} query block #{}",
                    session_index,
                    query_block_number
                );
                None
            }
            Err(e) => {
                log::warn!(
                    target: LOG_TARGET,
                    "Failed to get block hash for session {} query block #{}: {}",
                    session_index,
                    query_block_number,
                    e
                );
                None
            }
        };

        if runtime_result.is_some() {
            return runtime_result;
        }

        // (C) Last resort: the runtime API failed (e.g. a warp node querying a pre-warp session
        //     just ABOVE the last recorded change, where there is no historical state and (A) was
        //     skipped because `session_index > max_map_key`). Fall back to a floor-lookup over the
        //     warp map. Empty on full-history nodes, so this preserves their `None` result.
        if let Some(set) = floor_lookup_warp_map(&warp_map, session_index) {
            let authority_set = Self::to_authority_set(set);
            log::debug!(
                target: LOG_TARGET,
                "Resolved historical session {} from warp authority map (last-resort fallback)",
                session_index
            );
            self.historical_authority_set = Some((session_index, authority_set.clone()));
            return Some(authority_set);
        }

        None
    }

    // Validator identity and voting-power queries

    fn handle_validator_ids_hash(
        &mut self,
        session_index: SessionIndex,
        sender: oneshot::Sender<B::Hash>,
    ) {
        let validator_ids: Vec<ValidatorId> =
            if let Some(set) = self.try_get_authority_set_from_new(session_index) {
                set.keys().cloned().collect()
            } else if let Some(set) = self.try_get_authority_set_from_historical(session_index) {
                set.keys().cloned().collect()
            } else {
                Vec::new()
            };

        let hash = hash_of::<B>(validator_ids.encode().as_ref());
        let _ = sender.send(hash);
    }

    fn handle_local_authority_id(
        &self,
        session_index: SessionIndex,
        sender: oneshot::Sender<Option<AuthorityId>>,
    ) {
        // for authority not in the committee of this session
        // local validator id is none
        let Some(local_validator_id) = &self.local_validator_id else {
            let _ = sender.send(None);
            return;
        };

        let local_authority_id = self
            .get_authority_info(session_index, local_validator_id)
            .map(|auth_info| auth_info.1.clone());

        let _ = sender.send(local_authority_id);
    }

    fn handle_get_authority_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
        sender: oneshot::Sender<Option<AuthorityId>>,
    ) {
        let authority_id = self
            .get_authority_info(session_index, id)
            .map(|auth_info| auth_info.1.clone());

        let _ = sender.send(authority_id);
    }

    fn handle_local_auth_disc_id(
        &self,
        session_index: SessionIndex,
        sender: oneshot::Sender<Option<AuthorityDiscoveryId>>,
    ) {
        // for authority not in the committee of this session
        // local validator id is none
        let Some(local_validator_id) = &self.local_validator_id else {
            let _ = sender.send(None);
            return;
        };

        let auth_disc_id = self
            .get_authority_info(session_index, local_validator_id)
            .map(|auth_info| auth_info.3.clone());

        let _ = sender.send(auth_disc_id);
    }

    fn handle_get_auth_disc_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
        sender: oneshot::Sender<Option<AuthorityDiscoveryId>>,
    ) {
        let auth_disc_id = self
            .get_authority_info(session_index, id)
            .map(|auth_info| auth_info.3.clone());

        let _ = sender.send(auth_disc_id);
    }

    fn handle_local_validator_id(&self, sender: oneshot::Sender<Option<ValidatorId>>) {
        let _ = sender.send(self.local_validator_id.clone());
    }

    fn handle_get_bls_public(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
        sender: oneshot::Sender<Option<PublicKey>>,
    ) {
        let bls_pk = self
            .get_authority_info(session_index, id)
            .map(|auth_info| PublicKey::from(auth_info.2));

        let _ = sender.send(bls_pk);
    }

    fn handle_total_voting_power(
        &self,
        session_index: SessionIndex,
        sender: oneshot::Sender<usize>,
    ) {
        let power = match self.try_get_authority_set_from_new(session_index) {
            Some(set) => set.len(),
            None => 0,
        };
        let _ = sender.send(power);
    }

    fn handle_quorum_voting_power(
        &self,
        session_index: SessionIndex,
        sender: oneshot::Sender<usize>,
    ) {
        let power = match self.try_get_authority_set_from_new(session_index) {
            Some(set) => set.len(),
            None => 0,
        };
        let _ = sender.send(quorum_voting_power_from_total(power));
    }

    fn handle_get_validator_ids(
        &mut self,
        session_index: SessionIndex,
        sender: oneshot::Sender<Arc<Vec<ValidatorId>>>,
    ) {
        let mapping = if let Some(set) = self.try_get_authority_set_from_new(session_index) {
            let validator_ids: Vec<ValidatorId> = set.keys().cloned().collect();
            Arc::new(validator_ids)
        } else if let Some(set) = self.try_get_authority_set_from_historical(session_index) {
            let validator_ids: Vec<ValidatorId> = set.keys().cloned().collect();
            Arc::new(validator_ids)
        } else {
            Arc::new(Vec::new())
        };

        let _ = sender.send(mapping);
    }

    fn get_authority_info(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<&AuthorityInfo> {
        self.try_get_authority_set_from_new(session_index)
            .and_then(|set| set.get(id))
    }

    fn to_authority_set(
        auths: Vec<(AccountId, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId)>,
    ) -> AuthoritySet {
        let set: AuthoritySet = auths
            .into_iter()
            .map(|info| {
                let key = info.0.clone();
                (key, info)
            })
            .collect();
        set
    }
}

#[async_trait::async_trait]
impl<B: BlockT> SessionAuthorityProvider<B> for SessionInfoService<B> {
    async fn is_authoritiy_for_current_session(&self) -> bool {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::IsAuthorityForCurrentSession(tx))
            .await
            .ok();

        rx.await.unwrap_or(false)
    }

    async fn current_session_index(&self) -> SessionIndex {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::CurrentSessionIndex(tx))
            .await
            .ok();

        rx.await.unwrap_or(0)
    }

    async fn historical_session_index(&self) -> SessionIndex {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::HistoricalSessionIndex(tx))
            .await
            .ok();

        rx.await.unwrap_or(GENESIS_SESSION_INDEX)
    }

    async fn authorities(&self, session_index: SessionIndex) -> Option<AuthoritySet> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetAuthorities(session_index, tx))
            .await
            .ok();
        // Bounded wait: a *dead* worker drops the sender (so `rx.await` errors and yields `None`),
        // but a *stuck-alive* worker would otherwise hang this await forever. Cap it with a timeout
        // (reusing `tokio::time`, already a crate dep) so callers degrade to `None` instead of
        // blocking. On timeout we treat it as "no authorities" — same as a dead worker.
        let response = match tokio::time::timeout(GET_AUTHORITIES_TIMEOUT, rx).await {
            Ok(res) => res.ok().flatten(),
            Err(_elapsed) => {
                log::warn!(
                    target: LOG_TARGET,
                    "Timed out waiting for authorities of session {} from worker",
                    session_index
                );
                None
            }
        };
        // avoid returns an empty map
        response.and_then(|set| if set.is_empty() { None } else { Some(set) })
    }

    async fn validator_ids_hash(&self, session_index: SessionIndex) -> B::Hash {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::ValidatorIdsHash(session_index, tx))
            .await
            .ok();

        rx.await.unwrap_or(B::Hash::default())
    }

    async fn local_authority_id(&self, session_index: SessionIndex) -> Option<AuthorityId> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::LocalAuthorityId(session_index, tx))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn get_authority_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<AuthorityId> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetAuthorityId(
                session_index,
                id.clone(),
                tx,
            ))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn local_auth_disc_id(
        &self,
        session_index: SessionIndex,
    ) -> Option<AuthorityDiscoveryId> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::LocalAuthDiscId(session_index, tx))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn get_auth_disc_id(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<AuthorityDiscoveryId> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetAuthDiscId(
                session_index,
                id.clone(),
                tx,
            ))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn get_bls_public(
        &self,
        session_index: SessionIndex,
        id: &ValidatorId,
    ) -> Option<PublicKey> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetBlsPublc(
                session_index,
                id.clone(),
                tx,
            ))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn local_validator_id(&self) -> Option<ValidatorId> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::LocalValidatorId(tx))
            .await
            .ok();

        rx.await.ok().flatten()
    }

    async fn total_voting_power(&self, session_index: SessionIndex) -> usize {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::TotalVotingPower(session_index, tx))
            .await
            .ok();

        rx.await.unwrap_or(usize::MAX)
    }

    async fn quorum_voting_power(&self, session_index: SessionIndex) -> usize {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::QuorumVotingPower(session_index, tx))
            .await
            .ok();

        rx.await.unwrap_or(0)
    }

    async fn advance_current_session(&self) -> SessionIndex {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::AdvanceCurrentSession(tx))
            .await
            .ok();

        rx.await.unwrap_or(0)
    }

    async fn advance_historical_session(&self, block_number: NumberFor<B>) -> SessionIndex {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::AdvanceHistoricalSession(
                block_number,
                tx,
            ))
            .await
            .ok();

        rx.await.unwrap_or(0)
    }

    async fn session_index_by_number(&self, block_number: NumberFor<B>) -> SessionIndex {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::SessionIndexByNumber(block_number, tx))
            .await
            .ok();

        rx.await.unwrap_or(GENESIS_SESSION_INDEX)
    }

    async fn get_validator_ids(&self, session_index: SessionIndex) -> Arc<Vec<ValidatorId>> {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::GetValidatorIds(session_index, tx))
            .await
            .ok();

        rx.await.unwrap_or_else(|_| Arc::new(Vec::new()))
    }

    async fn should_end_session(&self, block_number: NumberFor<B>) -> bool {
        let (tx, rx) = oneshot::channel();

        self.to_worker
            .send(ServicetoWorkerMsg::ShouldEndSession(block_number, tx))
            .await
            .ok();

        rx.await.unwrap_or(false)
    }

    async fn should_end_session_by_calculation(&self, block_number: NumberFor<B>) -> bool {
        let number: U256 = block_number.into();
        let offset: U256 = U256::from(self.offset);
        let period: U256 = U256::from(self.period);

        // Direct implementation from pallet_session::PeriodicSessions
        // fn should_end_session(now: BlockNumber) -> bool {
        //     let offset = Offset::get();
        //     now >= offset && ((now - offset) % Period::get()).is_zero()
        // }
        number >= offset && ((number - offset) % period).is_zero()
    }

    async fn is_first_block_of_session(&self, block_number: NumberFor<B>) -> bool {
        use sp_runtime::traits::One;

        // First block of session means previous block was the last block of session
        if block_number <= NumberFor::<B>::one() {
            // Block 0 or 1 cannot have a previous block to check
            return false;
        }

        let prev_block = block_number - NumberFor::<B>::one();
        self.should_end_session(prev_block).await
    }

    /// NOTICE:
    /// if Period and Offset have been changed on the network
    /// is_number_match_session will be incorrect
    async fn is_number_match_session(
        &self,
        block_number: NumberFor<B>,
        session_index: SessionIndex,
    ) -> bool {
        let number: U256 = block_number.into();
        let offset: U256 = U256::from(self.offset);
        let period: U256 = U256::from(self.period);
        let session: U256 = U256::from(session_index);

        // Before offset, only genesis session (0) exists
        if number < offset {
            return session_index == GENESIS_SESSION_INDEX;
        }

        // Calculate the range for the given session
        // Session N contains blocks [offset + N * period, offset + (N+1) * period]
        // For example, if offset=0, period=1000:
        // - Session 0: [0, 1000] (1001 blocks)
        // - Session 1: [1001, 2001] (1001 blocks)
        let session_start = offset + session * period;
        let session_end = offset + (session + U256::one()) * period;

        number >= session_start && number <= session_end
    }
}

#[cfg(test)]
#[path = "../unit_tests/session_info_provider.rs"]
mod tests;
