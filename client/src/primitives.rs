use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    hash::Hash,
    sync::{Arc, Mutex},
    time::Duration,
};

use codec::{Decode, Encode};
use sc_client_api::Backend;
use sp_consensus_hotstuff::{
    consensus::{ConsensusLog, HOTSTUFF_CONSENSUS_ID},
    AccountId, AuthorityDiscoveryId, AuthorityId, BlsPublicBytes, SessionIndex,
};
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::{
    traits::{Block as BlockT, Header},
    Digest, OpaqueExtrinsic,
};

use crate::{
    client::HotstuffClient,
    error::{HotstuffError, HotstuffResult},
};

pub type AuxStorePrefix = [u8; 4];
pub type ValidatorId = AccountId;
pub type AuthorityInfo = (AccountId, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId);
pub type AuthoritySet = BTreeMap<ValidatorId, AuthorityInfo>;
pub const DEFAULT_EXTENDED_FROM_DEPTH: usize = 2;

/// Creates a default (zero) ValidatorId.
/// This is useful as a fallback value when validator selection fails.
/// If the account ID size changes in the future, only this function needs to be updated.
pub fn default_validator_id() -> ValidatorId {
    AccountId::new([0u8; 32])
}

pub const QC_BY_BLOCK_PREFIX: AuxStorePrefix = *b"hs01";
pub const QC_BY_DIGEST_PREFIX: AuxStorePrefix = *b"hs02";

pub type ViewNumber = u64;

/// View number for GB
pub const GENESIS_VIEW: ViewNumber = 1;
/// View number for parent block of GB
#[allow(unused)]
pub const GENESIS_PREV_VIEW: ViewNumber = GENESIS_VIEW - 1;
pub const GENESIS_SESSION_INDEX: SessionIndex = 0;

pub const VIEW_DUR_START_TIMEOUT_MS: f64 = 3000.0;
pub const VIEW_DUR_MAX_TIMEOUT_MS: f64 = 3000.0;
pub const VIEW_DUR_MIN_TIMEOUT_MS: f64 = 5.0;
// By reducing sample size and increasing multiplier,
// the view_duration can adjust more quickly to accommodate fluctuations in transaction traffic.
// In other words, it takes fewer timeouts to reach an appropriate view duration, which,
// under the multi-TC feature, greatly reduces the number of timeout messages broadcast across the network.
pub const VIEW_DUR_SAMPLE_SIZE: u64 = 10;
pub const VIEW_DUR_MULTIPLIER: f64 = 1.5;
// Reserved peers will be refreshed every 5 minutes to ensure that the network can adapt to changes in peer availability and maintain a healthy set of connections.
pub const REFRESH_RESERVED_PEERS_INTERVAL_SECS: u64 = 120;

// max txs limit to propose
pub const MAX_TXS_LIMIT: usize = 4_096;
pub const MAX_PROPOSAL_TX_BYTES: usize = 768 * 1024;
pub const CHANNEL_CAPACITY: usize = 1_000;

pub const PEER_WAIT_INTERVAL: Duration = Duration::from_millis(200);

/// Retry with exponential backoff
///
/// # Arguments
/// * `$operation` - The operation to retry (must return Result<T, E>)
/// * `$max_retries` - Maximum number of retry attempts (default: 5)
/// * `$base_delay_ms` - Base delay in milliseconds for exponential backoff (default: 100)
/// * `$log_target` - Log target string for logging
/// * `$operation_name` - Human-readable operation name for logging
///
/// # Example
/// ```ignore
/// let result = retry_with_backoff!(
///     self.refresh(),
///     5,
///     100,
///     "my-module",
///     "refresh operation"
/// );
/// ```
#[macro_export]
macro_rules! retry_with_backoff {
    ($operation:expr, $max_retries:expr, $base_delay_ms:expr, $log_target:expr, $operation_name:expr) => {{
        let max_retries: u32 = $max_retries;
        let base_delay_ms: u64 = $base_delay_ms;
        let mut result = None;

        for attempt in 0..max_retries {
            match $operation {
                Ok(val) => {
                    if attempt > 0 {
                        log::info!(
                            target: $log_target,
                            "{} succeeded on attempt {}",
                            $operation_name,
                            attempt + 1
                        );
                    }
                    result = Some(Ok(val));
                    break;
                }
                Err(e) => {
                    if attempt < max_retries - 1 {
                        let delay_ms = base_delay_ms * 2_u64.pow(attempt);
                        log::warn!(
                            target: $log_target,
                            "{} failed (attempt {}/{}): {:?}, retrying in {}ms",
                            $operation_name,
                            attempt + 1,
                            max_retries,
                            e,
                            delay_ms
                        );
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    } else {
                        log::error!(
                            target: $log_target,
                            "{} failed after {} attempts: {:?}",
                            $operation_name,
                            max_retries,
                            e,
                        );
                        result = Some(Err(e));
                    }
                }
            }
        }
        result.expect("retry loop should always produce a result")
    }};

    // Simplified version with default values: 5 retries, 100ms base delay
    ($operation:expr, $log_target:expr, $operation_name:expr) => {
        retry_with_backoff!($operation, 5, 100, $log_target, $operation_name)
    };
}

#[allow(unused)]
pub fn bytes_to_hash<B: BlockT>(bytes: &[u8]) -> B::Hash {
    B::Hash::decode(&mut &bytes[..]).expect("bytes must be a valid hash encoding")
}

pub fn opaque_exts_2_exts<B: BlockT>(txs: Vec<OpaqueExtrinsic>) -> Vec<B::Extrinsic> {
    txs.into_iter()
        .filter_map(|ox| {
            let buf = ox.encode();
            let mut slice: &[u8] = buf.as_ref();
            B::Extrinsic::decode(&mut slice).ok()
        })
        .collect()
}

pub fn exts_2_opaque_exts<B: BlockT>(txs: Vec<Arc<B::Extrinsic>>) -> Vec<OpaqueExtrinsic> {
    txs.into_iter()
        .map(|tx| {
            let bytes = (*tx).encode();
            OpaqueExtrinsic::try_from_encoded_extrinsic(&bytes)
                .expect("encoded extrinsics should decode as OpaqueExtrinsic")
        })
        .collect::<Vec<OpaqueExtrinsic>>()
}

pub fn extended_from<B, BE, C>(
    client: &C,
    block_hash: &B::Hash,
    ancestor_hash: &B::Hash,
) -> HotstuffResult<bool>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
{
    extended_from_with_depth::<B, BE, C>(
        client,
        block_hash,
        ancestor_hash,
        DEFAULT_EXTENDED_FROM_DEPTH,
    )
}

pub fn extended_from_with_depth<B, BE, C>(
    client: &C,
    block_hash: &B::Hash,
    ancestor_hash: &B::Hash,
    depth: usize,
) -> HotstuffResult<bool>
where
    B: BlockT,
    BE: Backend<B>,
    C: HotstuffClient<B, BE>,
{
    if block_hash == ancestor_hash {
        return Ok(true);
    }

    let mut cursor = block_hash.clone();
    for _ in 0..depth {
        let Some(header) = client
            .header(cursor.clone())
            .map_err(|error| HotstuffError::ClientImport(error.to_string()))?
        else {
            return Ok(false);
        };

        let parent_hash = header.parent_hash().clone();
        if parent_hash == *ancestor_hash {
            return Ok(true);
        }
        if parent_hash == cursor {
            return Ok(false);
        }
        cursor = parent_hash;
    }

    Ok(false)
}

#[allow(unused)]
pub fn qc_by_block_key<B: BlockT>(hash: &B::Hash) -> Vec<u8> {
    let mut k = QC_BY_BLOCK_PREFIX.to_vec();
    k.extend_from_slice(hash.as_ref());
    k
}

#[allow(unused)]
pub fn qc_by_digest_key<B: BlockT>(qc_hash: &B::Hash) -> Vec<u8> {
    let mut k = QC_BY_DIGEST_PREFIX.to_vec();
    k.extend_from_slice(qc_hash.as_ref());
    k
}

#[macro_export]
macro_rules! measure_time {
    ($label:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result = { $block };
        let elapsed = start.elapsed();
        log::trace!(target: LOG_TARGET, "measure_time: {} took {:?}", $label, elapsed);
        result
    }};
}

#[macro_export]
macro_rules! measure_time_with_item {
    ($label:expr, $total:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result = { $block };
        let elapsed = start.elapsed();
        let total_items = $total;
        if total_items > 0 {
            let per_item = elapsed / total_items as u32;
            log::trace!(
                target: LOG_TARGET,
                "measure_time: {} took {:?} for {} items (avg {:?} per item)",
                $label,
                elapsed,
                total_items,
                per_item
            );
        } else {
            log::trace!(target: LOG_TARGET, "measure_time: {} took {:?} for 0 items", $label, elapsed);
        }
        result
    }};
}

pub struct LruCache<K: Eq + Hash + Clone> {
    capacity: usize,
    queue: VecDeque<K>,
    map: HashMap<K, ()>,
}

impl<K: Eq + Hash + Clone> Clone for LruCache<K> {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            queue: self.queue.clone(),
            map: self.map.clone(),
        }
    }
}

impl<K: Eq + Hash + Clone> LruCache<K> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, key: K) {
        if self.map.contains_key(&key) {
            self.queue.retain(|k| k != &key);
        } else if self.queue.len() == self.capacity {
            if let Some(old) = self.queue.pop_front() {
                self.map.remove(&old);
            }
        }
        self.queue.push_back(key.clone());
        self.map.insert(key, ());
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
}

impl<K: Eq + Hash + Clone> fmt::Debug for LruCache<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LruCache")
            .field("capacity", &self.capacity)
            .field("len", &self.queue.len())
            .finish_non_exhaustive()
    }
}

#[allow(unused)]
pub struct SharedLru<K: Eq + Hash + Clone> {
    inner: Mutex<LruCache<K>>,
}

impl<K: Eq + Hash + Clone> Clone for SharedLru<K> {
    fn clone(&self) -> Self {
        let inner = self.inner.lock().expect("SharedLru mutex poisoned").clone();
        Self {
            inner: Mutex::new(inner),
        }
    }
}

impl<K: Eq + Hash + Clone> fmt::Debug for SharedLru<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedLru").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash + Clone> SharedLru<K> {
    #[allow(unused)]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    #[allow(unused)]
    pub fn insert(&self, key: K) {
        self.inner
            .lock()
            .expect("SharedLru mutex poisoned")
            .insert(key);
    }

    #[allow(unused)]
    pub fn contains(&self, key: &K) -> bool {
        self.inner
            .lock()
            .expect("SharedLru mutex poisoned")
            .contains(key)
    }
}

#[allow(dead_code)]
pub fn find_block_proposer(digest: &Digest) -> Option<ValidatorId> {
    let id = OpaqueDigestItemId::Consensus(&HOTSTUFF_CONSENSUS_ID);

    let filter_log = |log: ConsensusLog| match log {
        ConsensusLog::Proposer(leader_id) => Some(leader_id),
        _ => None,
    };

    digest.convert_first(|l| l.try_to(id).and_then(filter_log))
}

/// Extracts the `(next_session_index, authority_set_hash)` carried by a
/// `ConsensusLog::NextAuthoritySet` digest, if present. Mirrors
/// [`find_block_proposer`].
pub fn find_next_authority_set(digest: &Digest) -> Option<(SessionIndex, [u8; 32])> {
    let id = OpaqueDigestItemId::Consensus(&HOTSTUFF_CONSENSUS_ID);

    let filter_log = |log: ConsensusLog| match log {
        ConsensusLog::NextAuthoritySet {
            next_session_index,
            authority_set_hash,
        } => Some((next_session_index, authority_set_hash)),
        _ => None,
    };

    // find the first consensus digest with the right ID which converts to
    // the right kind of consensus log.
    digest.convert_first(|l| l.try_to(id).and_then(filter_log))
}

#[cfg(test)]
mod find_next_authority_set_tests {
    use super::*;
    use codec::Encode;
    use sp_runtime::DigestItem;

    #[test]
    fn extracts_next_authority_set() {
        let log = ConsensusLog::NextAuthoritySet {
            next_session_index: 7,
            authority_set_hash: [9u8; 32],
        };
        let digest = Digest {
            logs: vec![DigestItem::Consensus(HOTSTUFF_CONSENSUS_ID, log.encode())],
        };
        assert_eq!(find_next_authority_set(&digest), Some((7, [9u8; 32])));
    }

    #[test]
    fn ignores_other_consensus_logs() {
        // A `Proposer` consensus item must not match.
        let proposer = ConsensusLog::Proposer(default_validator_id());
        let digest = Digest {
            logs: vec![DigestItem::Consensus(
                HOTSTUFF_CONSENSUS_ID,
                proposer.encode(),
            )],
        };
        assert_eq!(find_next_authority_set(&digest), None);
    }

    #[test]
    fn empty_digest_yields_none() {
        let digest = Digest { logs: vec![] };
        assert_eq!(find_next_authority_set(&digest), None);
    }
}
