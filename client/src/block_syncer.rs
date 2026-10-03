use sc_network::PeerId;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};

use crate::network::Syncing;

const LOG_TARGET: &str = "sc-consensus-hotstuff::block-syncer";
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RETRIES: u32 = 3;

/// Sync request state tracking
#[derive(Debug, Clone)]
struct SyncRequest<B: BlockT> {
    #[allow(unused)]
    block_hash: B::Hash,
    block_number: NumberFor<B>,
    retry_count: u32,
    last_attempt: Instant,
    candidate_peers: HashSet<PeerId>,
    requested_peers: HashSet<PeerId>,
    retry_interval: Duration,
}

impl<B: BlockT> SyncRequest<B> {
    fn new(
        block_hash: B::Hash,
        block_number: NumberFor<B>,
        peers: Vec<PeerId>,
        retry_interval: Duration,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            retry_count: 0,
            last_attempt: Instant::now(),
            candidate_peers: peers.into_iter().collect(),
            requested_peers: HashSet::new(),
            retry_interval,
        }
    }

    fn should_retry(&self, now: Instant) -> bool {
        self.retry_count < MAX_RETRIES
            && now.duration_since(self.last_attempt) >= self.retry_interval
    }

    fn increment_retry(&mut self) {
        self.retry_count += 1;
        self.last_attempt = Instant::now();
    }

    fn mark_attempt(&mut self) {
        self.last_attempt = Instant::now();
    }

    fn has_exhausted_retries(&self) -> bool {
        self.retry_count >= MAX_RETRIES
    }

    fn merge_peers(&mut self, peers: Vec<PeerId>) {
        self.candidate_peers.extend(peers);
    }
}

/// Message from Service to Worker
enum ServiceToWorkerMsg<B: BlockT> {
    #[allow(dead_code)]
    SyncBlock {
        peers: Vec<PeerId>,
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    },
    IsMajorSyncing {
        reply: oneshot::Sender<bool>,
    },
    BlockImported {
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    },
    #[allow(unused)]
    CheckRetries,
}

/// Service handle for requesting block synchronization
#[derive(Clone)]
pub struct BlockSyncerService<B: BlockT> {
    to_worker: Sender<ServiceToWorkerMsg<B>>,
}

impl<B: BlockT> BlockSyncerService<B> {
    /// Request to sync a block if not already requested recently
    #[allow(dead_code)]
    pub async fn sync_block(
        &self,
        peers: Vec<PeerId>,
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    ) {
        let _ = self
            .to_worker
            .send(ServiceToWorkerMsg::SyncBlock {
                peers,
                block_hash,
                block_number,
            })
            .await;
    }

    /// Notify that a block has been imported (to remove from pending queue)
    /// This will remove all pending requests with block_number <= imported block_number
    pub async fn notify_block_imported(&self, block_hash: B::Hash, block_number: NumberFor<B>) {
        let _ = self
            .to_worker
            .send(ServiceToWorkerMsg::BlockImported {
                block_hash,
                block_number,
            })
            .await;
    }

    /// Check if the node is in major syncing state
    pub async fn is_major_syncing(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .to_worker
            .send(ServiceToWorkerMsg::IsMajorSyncing { reply: tx })
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

/// Worker that processes sync requests with retry mechanism
pub struct BlockSyncerWorker<B, S>
where
    B: BlockT,
    S: Syncing<B> + Sync + 'static,
{
    sync: S,
    /// Pending sync requests with retry tracking
    pending_requests: HashMap<B::Hash, SyncRequest<B>>,
    from_service: Receiver<ServiceToWorkerMsg<B>>,
    /// Timer for periodic retry checks
    retry_interval: tokio::time::Interval,
    retry_every: Duration,
}

impl<B, S> BlockSyncerWorker<B, S>
where
    B: BlockT,
    S: Syncing<B> + Sync + 'static,
{
    /// Create a new BlockSyncer with service and worker
    pub fn new_with_service(sync: S) -> (Self, BlockSyncerService<B>) {
        Self::new_with_service_inner(sync, RETRY_INTERVAL)
    }

    fn new_with_service_inner(sync: S, retry_every: Duration) -> (Self, BlockSyncerService<B>) {
        let (tx, rx) = channel(100);

        let worker = Self {
            sync,
            pending_requests: HashMap::new(),
            from_service: rx,
            retry_interval: tokio::time::interval(retry_every),
            retry_every,
        };

        let service = BlockSyncerService { to_worker: tx };

        (worker, service)
    }

    /// Run the worker loop
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.from_service.recv() => match msg {
                    ServiceToWorkerMsg::SyncBlock {
                        peers,
                        block_hash,
                        block_number,
                    } => {
                        self.handle_sync_block(peers, block_hash, block_number).await;
                    },
                    ServiceToWorkerMsg::IsMajorSyncing { reply } => {
                        let is_syncing = self.sync.is_major_syncing();
                        let _ = reply.send(is_syncing);
                    },
                    ServiceToWorkerMsg::BlockImported { block_hash, block_number } => {
                        self.handle_block_imported(block_hash, block_number);
                    },
                    ServiceToWorkerMsg::CheckRetries => {
                        self.check_and_retry_requests().await;
                    },
                },
                _ = self.retry_interval.tick() => {
                    self.check_and_retry_requests().await;
                },
                else => {
                    // Channel closed, exit worker
                    log::debug!(target: LOG_TARGET, "BlockSyncerWorker channel closed, exiting");
                    break;
                }
            }
        }
    }

    async fn handle_sync_block(
        &mut self,
        peers: Vec<PeerId>,
        block_hash: B::Hash,
        block_number: NumberFor<B>,
    ) {
        // Check if already in pending queue
        if let Some(request) = self.pending_requests.get_mut(&block_hash) {
            request.merge_peers(peers);
            log::trace!(
                target: LOG_TARGET,
                "Block {:?} already in pending queue (retry: {}/{})",
                block_hash,
                request.retry_count,
                MAX_RETRIES
            );
            let _ = self.try_send_sync_request(block_hash, false);
            return;
        }

        // Create new request
        let request = SyncRequest::new(block_hash, block_number, peers, self.retry_every);
        log::info!(
            target: LOG_TARGET,
            "🔄 Adding sync request for block {:?} at height {:?}",
            block_hash,
            block_number
        );

        // Add to pending queue
        self.pending_requests.insert(block_hash, request);
        let _ = self.try_send_sync_request(block_hash, false);
    }

    fn handle_block_imported(&mut self, _block_hash: B::Hash, block_number: NumberFor<B>) {
        // Remove all pending requests with block_number <= imported block_number
        let mut removed_count = 0;
        self.pending_requests.retain(|hash, request| {
            if request.block_number <= block_number {
                log::info!(
                    target: LOG_TARGET,
                    "✅ Block {:?} at height {:?} imported, removed from pending queue (was at {} attempts)",
                    hash,
                    request.block_number,
                    request.retry_count + 1
                );
                removed_count += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        if removed_count > 0 {
            log::debug!(
                target: LOG_TARGET,
                "🧹 Cleaned {} pending requests at or below height {:?}",
                removed_count,
                block_number
            );
        }
    }

    async fn check_and_retry_requests(&mut self) {
        let now = Instant::now();
        let mut to_retry = Vec::new();
        let mut to_remove = Vec::new();

        // Collect requests that need retry or removal
        for (hash, request) in self.pending_requests.iter_mut() {
            if request.should_retry(now) {
                to_retry.push(*hash);
            }
        }

        // Perform retries
        for hash in to_retry {
            if let Some(request) = self.pending_requests.get(&hash) {
                log::debug!(
                    target: LOG_TARGET,
                    "🔁 Retrying sync request for block {:?} (attempt {}/{})",
                    hash,
                    request.retry_count,
                    MAX_RETRIES
                );
            }
            let sent = self.try_send_sync_request(hash, true);
            if let Some(request) = self.pending_requests.get(&hash) {
                if request.has_exhausted_retries() {
                    log::warn!(
                        target: LOG_TARGET,
                        "❌ Sync request for block {:?} exhausted all {} retries, removing from queue",
                        hash,
                        MAX_RETRIES
                    );
                    to_remove.push(hash);
                } else if !sent {
                    log::trace!(
                        target: LOG_TARGET,
                        "No new peers available to retry sync request for block {:?}",
                        hash,
                    );
                }
            }
        }

        // Remove exhausted requests
        for hash in to_remove {
            self.pending_requests.remove(&hash);
        }

        // Log pending queue status if not empty
        if !self.pending_requests.is_empty() {
            log::trace!(
                target: LOG_TARGET,
                "📋 Pending sync requests: {}",
                self.pending_requests.len()
            );
        }
    }

    fn try_send_sync_request(&mut self, block_hash: B::Hash, is_retry: bool) -> bool {
        let Some(request) = self.pending_requests.get_mut(&block_hash) else {
            return false;
        };

        if let Some(peer_id) = request
            .candidate_peers
            .iter()
            .find(|peer_id| !request.requested_peers.contains(peer_id))
            .copied()
        {
            log::debug!(
                target: LOG_TARGET,
                "📡 Requesting block {:?} at height {:?} from peer {:?}",
                block_hash,
                request.block_number,
                peer_id,
            );
            self.sync
                .set_sync_fork_request(vec![peer_id], block_hash, request.block_number);
            request.requested_peers.insert(peer_id);
            if is_retry {
                request.increment_retry();
            } else {
                request.mark_attempt();
            }
            return true;
        }

        log::debug!(
            target: LOG_TARGET,
            "⏸️ Skip sync request for block {:?}: no unused peers available",
            block_hash,
        );
        request.mark_attempt();
        false
    }
}
