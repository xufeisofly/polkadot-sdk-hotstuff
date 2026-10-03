//! Tests for Pacemaker

use crate::crypto::{AggregateSignature, AuthorityCrypto, Crypto, QuorumCrypto};
use crate::error::CryptoError;
use crate::messages::{ConsensusMessage, ConsensusOp, Timeout, TimeoutParams, QC};
use crate::network::{GossipCmd, GossipSenderHandle, HotstuffNetworkSender, Network};
use crate::pacemaker::Pacemaker;
use crate::primitives::{ValidatorId, ViewNumber};
use async_trait::async_trait;
use sc_network::{
    config::MultiaddrWithPeerId, NetworkEventStream, NetworkPeers, NetworkStateInfo, ObservedRole,
    PeerId, ProtocolName,
};
use sc_network_gossip::{Network as GossipNetwork, TopicNotification};
use sp_consensus_hotstuff::{AuthorityId, AuthoritySignature, SessionIndex};
use sp_core::H256;
use sp_runtime::generic::Header;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT};
use sp_runtime::AccountId32;
use sp_runtime::OpaqueExtrinsic;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use tokio::sync::mpsc;

type TestHeader = Header<u32, BlakeTwo256>;
type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

#[derive(Clone)]
struct MockNetwork {
    local_peer_id: PeerId,
}

impl MockNetwork {
    fn new() -> Self {
        Self {
            local_peer_id: PeerId::random(),
        }
    }
}

impl NetworkStateInfo for MockNetwork {
    fn external_addresses(&self) -> Vec<sc_network::Multiaddr> {
        Vec::new()
    }

    fn listen_addresses(&self) -> Vec<sc_network::Multiaddr> {
        Vec::new()
    }

    fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
}

impl NetworkEventStream for MockNetwork {
    fn event_stream(
        &self,
        _name: &'static str,
    ) -> Pin<Box<dyn futures::Stream<Item = sc_network::Event> + Send>> {
        Box::pin(futures::stream::pending())
    }
}

#[async_trait]
impl NetworkPeers for MockNetwork {
    fn set_authorized_peers(&self, _peers: HashSet<PeerId>) {}
    fn set_authorized_only(&self, _reserved_only: bool) {}
    fn add_known_address(&self, _peer: PeerId, _addr: sc_network::Multiaddr) {}
    fn report_peer(&self, _who: PeerId, _cost_benefit: sc_network::ReputationChange) {}
    fn disconnect_peer(&self, _who: PeerId, _protocol: ProtocolName) {}
    fn accept_unreserved_peers(&self) {}
    fn deny_unreserved_peers(&self) {}
    fn add_reserved_peer(&self, _peer: MultiaddrWithPeerId) -> Result<(), String> {
        Ok(())
    }
    fn remove_reserved_peer(&self, _peer: PeerId) {}
    fn set_reserved_peers(
        &self,
        _protocol: ProtocolName,
        _peers: HashSet<sc_network::Multiaddr>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn peer_reputation(&self, _who: &PeerId) -> i32 {
        0
    }
    fn add_peers_to_reserved_set(
        &self,
        _protocol: ProtocolName,
        _peers: HashSet<sc_network::Multiaddr>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn remove_peers_from_reserved_set(
        &self,
        _protocol: ProtocolName,
        _peers: Vec<PeerId>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn sync_num_connected(&self) -> usize {
        0
    }
    fn peer_role(&self, _who: PeerId, _handshake: Vec<u8>) -> Option<ObservedRole> {
        None
    }
    async fn reserved_peers(&self) -> Result<Vec<PeerId>, ()> {
        Ok(Vec::new())
    }
}

struct MockCrypto;

#[async_trait]
impl QuorumCrypto for MockCrypto {
    type B = TestBlock;
    type S = AggregateSignature;
    type H = H256;

    async fn sign(&self, _message: &Self::H) -> Result<Self::S, CryptoError> {
        Ok(AggregateSignature::default())
    }

    async fn combine(&self, _signatures: &[Self::S]) -> Result<Self::S, CryptoError> {
        Ok(AggregateSignature::default())
    }

    async fn verify(
        &self,
        _signature: &Self::S,
        _message: &Self::H,
        _session_index: SessionIndex,
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn verify_partial(
        &self,
        _signature: &Self::S,
        _message: &Self::H,
        _session_index: SessionIndex,
    ) -> Result<ValidatorId, CryptoError> {
        Err(CryptoError::VerifyFailed)
    }

    async fn batch_verify(
        &self,
        _signature: &Self::S,
        _batch: HashMap<ValidatorId, Self::H>,
        _session_index: SessionIndex,
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[async_trait]
impl AuthorityCrypto for MockCrypto {
    async fn authority_sign(
        &self,
        _message: &[u8],
        _session_index: SessionIndex,
    ) -> Result<AuthoritySignature, CryptoError> {
        use sp_core::crypto::UncheckedFrom;
        Ok(AuthoritySignature::unchecked_from([0u8; 64]))
    }

    async fn authority_verify(
        &self,
        _signature: &AuthoritySignature,
        _message: &[u8],
        _pk: &AuthorityId,
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[async_trait]
impl Crypto for MockCrypto {
    async fn collect_partial_sig(
        &self,
        _view: ViewNumber,
        _msg: &Self::H,
        _part_sig: Self::S,
        _session_index: SessionIndex,
    ) -> Option<Self::S> {
        Some(AggregateSignature::default())
    }

    async fn collecting_progress(
        &self,
        _view: ViewNumber,
        _msg: &Self::H,
        _session_index: SessionIndex,
    ) -> (usize, usize) {
        (0, 0)
    }

    async fn verify_qc(&self, _qc: &QC<Self::B>) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn verify_tc(&self, _tc: &crate::messages::TC<Self::B>) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn verify_agg_qc(
        &self,
        _agg_qc: &crate::messages::AggQC<Self::B>,
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_pacemaker_timeout_generation() {
    let network = MockNetwork::new();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let gossip_handle = GossipSenderHandle::new_for_test(network.clone(), cmd_tx);
    let (consensus_tx, _consensus_rx) = mpsc::channel(100);
    let hotstuff_network = HotstuffNetworkSender::new(gossip_handle, consensus_tx);

    let crypto = MockCrypto;
    let (_op_tx, op_rx) = mpsc::channel(100);

    let mut pacemaker = Pacemaker::new(hotstuff_network, crypto, op_rx);

    let view = 1;
    let session = 0;
    let local_id = AccountId32::new([0; 32]);
    let high_qc = QC::<TestBlock>::default();

    pacemaker
        .timeout(view, session, local_id, high_qc, None)
        .await;

    let cmd = cmd_rx.recv().await;
    assert!(cmd.is_some());
    match cmd.unwrap() {
        GossipCmd::Broadcast(_data) => {}
        _ => panic!("Expected Broadcast command"),
    }
}

#[tokio::test]
async fn test_pacemaker_timeout_broadcast() {
    let network = MockNetwork::new();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let gossip_handle = GossipSenderHandle::new_for_test(network.clone(), cmd_tx);
    let (consensus_tx, _consensus_rx) = mpsc::channel(100);
    let hotstuff_network = HotstuffNetworkSender::new(gossip_handle, consensus_tx);

    let crypto = MockCrypto;
    let (_op_tx, op_rx) = mpsc::channel(100);

    let mut pacemaker = Pacemaker::new(hotstuff_network, crypto, op_rx);

    let view = 1;
    let session = 0;
    let local_id = AccountId32::new([0; 32]);
    let high_qc = QC::<TestBlock>::default();

    pacemaker
        .timeout(view, session, local_id, high_qc, None)
        .await;

    let cmd = cmd_rx.recv().await;
    assert!(cmd.is_some());
    match cmd.unwrap() {
        GossipCmd::Broadcast(_data) => {
            // Success
        }
        _ => panic!("Expected Broadcast command"),
    }
}

#[tokio::test]
async fn test_pacemaker_run_loop() {
    let network = MockNetwork::new();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let gossip_handle = GossipSenderHandle::new_for_test(network.clone(), cmd_tx);
    let (consensus_tx, _consensus_rx) = mpsc::channel(100);
    let hotstuff_network = HotstuffNetworkSender::new(gossip_handle, consensus_tx);

    let crypto = MockCrypto;
    let (op_tx, op_rx) = mpsc::channel(100);

    let pacemaker = Pacemaker::new(hotstuff_network, crypto, op_rx);

    tokio::spawn(async move {
        pacemaker.run().await;
    });

    let view = 2;
    let session = 0;
    let local_id = AccountId32::new([0; 32]);
    let high_qc = QC::<TestBlock>::default();

    let params = TimeoutParams {
        view,
        session_index: session,
        local_id,
        high_qc,
        high_tc_opt: None,
    };

    op_tx.send(ConsensusOp::Timeout(params)).await.unwrap();

    let cmd = cmd_rx.recv().await;
    assert!(cmd.is_some());
    match cmd.unwrap() {
        GossipCmd::Broadcast(_data) => {}
        _ => panic!("Expected Broadcast command"),
    }
}
