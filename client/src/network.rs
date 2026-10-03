// Two peer-connection semantics affect Hotstuff behavior:
// - `p2p peers`: Peer-to-peer connections maintained by the Substrate networking layer.
//   All protocol traffic relies on these connections, including Hotstuff and sync.
//   Once a `peer_disconnected` event occurs, no message can be delivered to that peer.
// - `joined_authority_peers`: A validator-set connection allowlist maintained via
//   Hotstuff protocol reserved peers. It is only used for consensus message delivery.
//   Messages from non-reserved nodes are denied. This set is refreshed periodically,
//   and currently only authority nodes can be included.
use codec::{Decode, DecodeAll, Encode};
use sc_network::service::traits::{NotificationEvent, ValidationResult};
use sc_network::{
    Multiaddr, NetworkBlock, NetworkStateInfo, NetworkSyncForkRequest, NotificationService, PeerId,
    ProtocolName,
};
use sc_network_gossip::{Network as GossipNetwork, TopicNotification};
use sc_network_sync::SyncEventStream;
use sp_consensus::SyncOracle;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::{
    collections::HashSet,
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{messages::ConsensusMessage, peer_provider::PeerInfo, primitives::ViewNumber};
use tokio::sync::mpsc::{unbounded_channel, Sender, UnboundedReceiver, UnboundedSender};

const LOG_TARGET: &str = "sc-consensus-hotstuff::network";
const MAX_BATCH: usize = 1024;
const MAX_DRAIN_TIME: Duration = Duration::from_millis(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLifecycleEvent {
    NewPeer(PeerId),
    PeerDisconnected(PeerId),
}

#[derive(Debug, Clone)]
pub struct JoinedAuthorityPeersState {
    gossip_peers: HashSet<PeerId>,
    reserved_peers: Vec<PeerId>,
}

impl JoinedAuthorityPeersState {
    pub fn gossip_peers(&self) -> &HashSet<PeerId> {
        &self.gossip_peers
    }

    pub fn reserved_peers(&self) -> &[PeerId] {
        &self.reserved_peers
    }
}

/// A handle to the network.
///
/// Something that provides the capabilities needed for the `gossip_network::Network` trait.
pub trait Network<Block: BlockT>:
    GossipNetwork<Block> + NetworkStateInfo + Clone + Send + 'static
{
}

impl<Block, T> Network<Block> for T
where
    Block: BlockT,
    T: GossipNetwork<Block> + NetworkStateInfo + Clone + Send + 'static,
{
}

/// A handle to syncing-related services.
///
/// Something that provides the ability to set a fork sync request for a particular block.
pub trait Syncing<Block: BlockT>:
    NetworkSyncForkRequest<Block::Hash, NumberFor<Block>>
    + NetworkBlock<Block::Hash, NumberFor<Block>>
    + SyncEventStream
    + SyncOracle
    + Clone
    + Send
    + 'static
{
}

impl<Block, T> Syncing<Block> for T
where
    Block: BlockT,
    T: NetworkSyncForkRequest<Block::Hash, NumberFor<Block>>
        + NetworkBlock<Block::Hash, NumberFor<Block>>
        + SyncEventStream
        + SyncOracle
        + Clone
        + Send
        + 'static,
{
}

pub(super) struct GossipValidator<Block: BlockT> {
    view: parking_lot::RwLock<ViewNumber>,
    peers: parking_lot::RwLock<HashSet<PeerId>>,
    peer_event_tx: UnboundedSender<PeerLifecycleEvent>,
    _phantom: Option<PhantomData<Block>>,
}

impl<Block: BlockT> GossipValidator<Block> {
    /// Track the current view and the discovered authority peers.
    pub(super) fn new() -> (
        GossipValidator<Block>,
        UnboundedReceiver<PeerLifecycleEvent>,
    ) {
        let (peer_event_tx, peer_event_rx) = unbounded_channel();
        let val = GossipValidator {
            _phantom: None,
            view: parking_lot::RwLock::new(0),
            peers: parking_lot::RwLock::new(HashSet::new()),
            peer_event_tx,
        };

        (val, peer_event_rx)
    }

    pub fn set_peers(&self, new_set: HashSet<PeerId>) {
        let mut guard = self.peers.write();
        *guard = new_set;
    }

    pub fn get_peers(&self) -> HashSet<PeerId> {
        self.peers.read().clone()
    }

    pub fn set_view(&self, new_view: ViewNumber) {
        let mut view = self.view.write();
        *view = new_view
    }

    pub fn get_view(&self) -> ViewNumber {
        let view = self.view.read();
        *view
    }
}

impl<B: BlockT> GossipValidator<B> {
    fn accepts(&self, sender: &PeerId, data: &[u8]) -> bool {
        if !self.peers.read().contains(sender) {
            return false;
        }
        let Ok(message) = ConsensusMessage::<B>::decode_all(&mut &data[..]) else {
            return false;
        };
        let view = match message {
            ConsensusMessage::Vote(_) => return true,
            ConsensusMessage::Proposal(message) => message.view,
            ConsensusMessage::NewView(message) => message.view,
            ConsensusMessage::Timeout(message) => message.view,
        };
        self.get_view() <= 1 || view >= self.get_view()
    }
}

pub enum GossipCmd {
    Broadcast(Vec<u8>),
    SendTo(Vec<PeerId>, Vec<u8>),
}

#[derive(Clone)]
pub struct GossipSenderHandle<B: BlockT, N: Network<B>> {
    reserved: Arc<parking_lot::Mutex<Vec<PeerId>>>,
    cmd_tx: UnboundedSender<GossipCmd>,
    network: N,
    validator: Arc<GossipValidator<B>>,
    protocol_name: ProtocolName,
    _phantom: PhantomData<B>,
}

pub struct GossipReceiverHandle {
    notif_rx: UnboundedReceiver<TopicNotification>,
}

impl<B, N> GossipSenderHandle<B, N>
where
    B: BlockT,
    N: Network<B>,
{
    #[cfg(any(test))]
    pub fn new_for_test(network: N, cmd_tx: tokio::sync::mpsc::UnboundedSender<GossipCmd>) -> Self {
        let (validator, _) = GossipValidator::new();
        Self {
            reserved: Default::default(),
            cmd_tx,
            network,
            validator: Arc::new(validator),
            protocol_name: "/test/1".into(),
            _phantom: PhantomData,
        }
    }

    pub fn try_broadcast(&self, bytes: Vec<u8>) {
        let _ = self.cmd_tx.send(GossipCmd::Broadcast(bytes));
    }

    pub fn try_send_to(&self, peers: Vec<PeerId>, bytes: Vec<u8>) {
        let _ = self.cmd_tx.send(GossipCmd::SendTo(peers, bytes));
    }

    pub fn set_view(&self, view: ViewNumber) {
        self.validator.set_view(view);
    }

    pub fn set_joined_authority_peers(&self, new_peer_infos: Vec<PeerInfo>) {
        if new_peer_infos.is_empty() {
            log::trace!(target: LOG_TARGET, "new peers are none");
            return;
        }

        let prev_joined_peers = self.validator.get_peers();
        let peer_id_set: HashSet<PeerId> = new_peer_infos
            .iter()
            .map(|peer_info| peer_info.peer_id)
            .collect();

        self.validator.set_peers(peer_id_set.clone());

        // disconnect old
        let removed_peers: Vec<PeerId> = prev_joined_peers
            .difference(&peer_id_set)
            .cloned()
            .collect();
        for peer_id in removed_peers.iter() {
            if *peer_id == self.network.local_peer_id() {
                continue;
            }
            log::info!(target: LOG_TARGET, "Disconnect old validator peer: {:?}", peer_id);
            self.network
                .disconnect_peer(*peer_id, self.protocol_name.clone());
        }

        let peer_multiaddr_set: HashSet<Multiaddr> = new_peer_infos
            .iter()
            .filter_map(|peer_info| {
                if self.network.local_peer_id() == peer_info.peer_id {
                    None
                } else {
                    Some(peer_info.multiaddr.clone())
                }
            })
            .collect();
        log::trace!(
            target: LOG_TARGET,
            "set_reserved_peers input, protocol: {:?}, peers: {:?}",
            self.protocol_name,
            peer_multiaddr_set
        );
        let reserved_target_len = peer_multiaddr_set.len();
        match self
            .network
            .set_reserved_peers(self.protocol_name.clone(), peer_multiaddr_set)
        {
            Ok(()) => {
                *self.reserved.lock() = new_peer_infos
                    .iter()
                    .map(|p| p.peer_id)
                    .filter(|p| *p != self.network.local_peer_id())
                    .collect();
            }
            Err(e) => {
                log::warn!(
                    target: LOG_TARGET,
                    "set_reserved_peers failed, protocol: {:?}, target_peers: {}, err: {}",
                    self.protocol_name,
                    reserved_target_len,
                    e
                );
            }
        }
    }
}

impl GossipReceiverHandle {
    #[allow(unused)]
    pub async fn recv_notification(&mut self) -> Option<TopicNotification> {
        self.notif_rx.recv().await
    }
}

pub fn run_gossip_task<B: BlockT, N: Network<B>, S: Syncing<B>>(
    network: N,
    _sync: S,
    mut notification_service: Box<dyn NotificationService>,
    protocol_name: ProtocolName,
) -> (
    GossipSenderHandle<B, N>,
    GossipReceiverHandle,
    UnboundedReceiver<PeerLifecycleEvent>,
) {
    let (validator, peer_event_rx) = GossipValidator::new();
    let validator = Arc::new(validator);
    let validator_for_task = validator.clone();
    let task_network = network.clone();
    let (cmd_tx, mut cmd_rx) = unbounded_channel::<GossipCmd>();
    let (notif_tx, notif_rx) = unbounded_channel::<TopicNotification>();

    // Authorities already form a reserved full mesh. Messages were never retained
    // by the gossip engine; use the upstream notification API directly so both
    // litep2p and libp2p support asynchronous sends without SDK patches.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = notification_service.next_event() => match event {
                    Some(NotificationEvent::ValidateInboundSubstream { peer, handshake, result_tx }) => {
                        let result = if task_network.peer_role(peer, handshake).is_some() {
                            ValidationResult::Accept
                        } else {
                            ValidationResult::Reject
                        };
                        let _ = result_tx.send(result);
                    }
                    Some(NotificationEvent::NotificationStreamOpened { peer, handshake, .. }) => {
                        if task_network.peer_role(peer, handshake).is_some() {
                            log::info!(target: LOG_TARGET, "Hotstuff peer connected: {peer}");
                            let _ = validator_for_task.peer_event_tx.send(PeerLifecycleEvent::NewPeer(peer));
                        }
                    }
                    Some(NotificationEvent::NotificationStreamClosed { peer }) => {
                        let _ = validator_for_task.peer_event_tx.send(PeerLifecycleEvent::PeerDisconnected(peer));
                    }
                    Some(NotificationEvent::NotificationReceived { peer, notification }) => {
                        if validator_for_task.accepts(&peer, &notification) {
                            let _ = notif_tx.send(TopicNotification { sender: Some(peer), message: notification });
                        }
                    }
                    None => break,
                },
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    let (peers, bytes) = match cmd {
                        GossipCmd::Broadcast(bytes) => (validator_for_task.get_peers().into_iter().collect(), bytes),
                        GossipCmd::SendTo(peers, bytes) => (peers, bytes),
                    };
                    for peer in peers {
                        // Broadcasts are already delivered locally by HotstuffNetworkSender.
                        if peer == task_network.local_peer_id() { continue; }
                        if let Err(error) = notification_service.send_async_notification(&peer, bytes.clone()).await {
                            log::debug!(target: LOG_TARGET, "Sending consensus message to {peer} failed: {error:?}");
                        }
                    }
                }
            }
        }
    });

    (
        GossipSenderHandle::<B, N> {
            reserved: Default::default(),
            cmd_tx,
            network,
            validator: validator.clone(),
            protocol_name,
            _phantom: PhantomData,
        },
        GossipReceiverHandle { notif_rx },
        peer_event_rx,
    )
}

pub struct HotstuffNetworkSender<B: BlockT, N: Network<B> + Send> {
    gossip: GossipSenderHandle<B, N>,
    consensus_msg_tx: Sender<ConsensusMessage<B>>, // to consensus_worker
}

impl<B: BlockT, N: Network<B>> Clone for HotstuffNetworkSender<B, N> {
    fn clone(&self) -> Self {
        Self {
            gossip: self.gossip.clone(),
            consensus_msg_tx: self.consensus_msg_tx.clone(),
        }
    }
}

impl<B, N> HotstuffNetworkSender<B, N>
where
    B: BlockT,
    N: Network<B>,
{
    pub fn new(
        gossip: GossipSenderHandle<B, N>,
        consensus_msg_tx: Sender<ConsensusMessage<B>>,
    ) -> Self {
        Self {
            gossip,
            consensus_msg_tx,
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.gossip.network.local_peer_id()
    }

    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.gossip.network.listen_addresses()
    }

    #[allow(unused)]
    pub fn external_addresses(&self) -> Vec<Multiaddr> {
        self.gossip.network.external_addresses()
    }

    pub fn broadcast_message(&self, msg: ConsensusMessage<B>) {
        let bytes = msg.encode();
        self.gossip.try_broadcast(bytes);
        if let Err(e) = self.consensus_msg_tx.try_send(msg) {
            log::warn!(target: LOG_TARGET, "broadcast to local network error: {}", e);
        }
    }

    pub fn send_message(&self, mut whos: Vec<PeerId>, message: ConsensusMessage<B>) {
        // Deliver locally when the recipients include this node.
        let has_local = whos.iter().position(|p| *p == self.local_peer_id());

        if let Some(pos) = has_local {
            whos.remove(pos);

            if let Err(e) = self.consensus_msg_tx.try_send(message.clone()) {
                log::warn!(target: LOG_TARGET, "send to local network error: {}", e);
            }
        }

        if !whos.is_empty() {
            self.gossip.try_send_to(whos, message.encode());
        }
    }

    pub fn set_view(&self, view: ViewNumber) {
        self.gossip.set_view(view);
    }

    pub fn set_joined_authority_peers(&self, new_peer_infos: Vec<PeerInfo>) {
        self.gossip.set_joined_authority_peers(new_peer_infos);
    }

    #[allow(unused)]
    pub fn gossip_peer_num(&self) -> usize {
        self.gossip.network.sync_num_connected()
    }

    pub async fn protocol_reserved_peers(&self) -> Vec<PeerId> {
        self.gossip.reserved.lock().clone()
    }

    pub async fn protocol_reserved_peers_len(&self) -> usize {
        self.protocol_reserved_peers().await.len()
    }

    pub async fn joined_authority_peers_state(&self) -> JoinedAuthorityPeersState {
        JoinedAuthorityPeersState {
            gossip_peers: self.gossip.validator.get_peers(),
            reserved_peers: self.protocol_reserved_peers().await,
        }
    }
}

// TODO: make consensus network a tokio task
// use channels to send or broadcast messages
pub struct ConsensusNetwork<B: BlockT> {
    gossip: GossipReceiverHandle,
    consensus_msg_tx: Sender<ConsensusMessage<B>>, // to consensus_worker
}

impl<B> ConsensusNetwork<B>
where
    B: BlockT,
{
    pub fn new(
        gossip: GossipReceiverHandle,
        consensus_msg_tx: Sender<ConsensusMessage<B>>,
    ) -> Self {
        Self {
            gossip,
            consensus_msg_tx,
        }
    }

    pub async fn run(mut self) {
        let rx = &mut self.gossip.notif_rx;

        while let Some(first) = rx.recv().await {
            // handle the first msg
            match Decode::decode(&mut &first.message[..]) {
                Ok::<ConsensusMessage<B>, _>(m) => {
                    let _ = self.consensus_msg_tx.try_send(m);
                }
                Err(e) => log::warn!(target: LOG_TARGET, "decode consensus message failed: {e}"),
            }

            // drain the rest
            let t0 = Instant::now();
            let mut n = 0usize;
            while n < MAX_BATCH && t0.elapsed() < MAX_DRAIN_TIME {
                match rx.try_recv() {
                    Ok(notif) => {
                        match Decode::decode(&mut &notif.message[..]) {
                            Ok::<ConsensusMessage<B>, _>(m) => {
                                let _ = self.consensus_msg_tx.try_send(m);
                            }
                            Err(e) => {
                                log::warn!(target: LOG_TARGET, "decode consensus message failed: {e}")
                            }
                        }
                        n += 1;
                    }
                    Err(_) => break, // Empty/Closed
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Timeout;
    use sp_runtime::{generic, traits::BlakeTwo256, AccountId32, OpaqueExtrinsic};

    #[test]
    fn notification_filter_requires_authority_canonical_message_and_current_view() {
        type Block = generic::Block<generic::Header<u32, BlakeTwo256>, OpaqueExtrinsic>;
        let (validator, _) = GossipValidator::<Block>::new();
        let peer = PeerId::random();
        let bytes =
            ConsensusMessage::Timeout(Timeout::<Block>::new(AccountId32::new([1; 32]), 5, 0, None))
                .encode();
        assert!(!validator.accepts(&peer, &bytes));
        validator.set_peers([peer].into_iter().collect());
        validator.set_view(5);
        assert!(validator.accepts(&peer, &bytes));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(!validator.accepts(&peer, &trailing));
        assert!(!validator.accepts(&peer, &[255]));
        validator.set_view(6);
        assert!(!validator.accepts(&peer, &bytes));
    }
}
