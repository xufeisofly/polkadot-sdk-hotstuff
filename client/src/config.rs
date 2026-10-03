use std::sync::Arc;

use array_bytes::bytes2hex;
use sc_chain_spec::ChainSpec;
use sc_network::{types::ProtocolName, NetworkBackend, NotificationService};
use sp_runtime::traits::Block as BlockT;

pub(crate) const HOTSTUFF_PROTOCOL_NAME: &str = "/hotstuff/1";

pub fn protocol_standard_name<Hash: AsRef<[u8]>>(
    genesis_hash: &Hash,
    chain_spec: &Box<dyn ChainSpec>,
) -> ProtocolName {
    let genesis_hash = genesis_hash.as_ref();
    let chain_prefix = match chain_spec.fork_id() {
        Some(fork_id) => format!("/{}/{}", bytes2hex("", genesis_hash), fork_id),
        None => format!("/{}", bytes2hex("", genesis_hash)),
    };
    format!("{}{}", chain_prefix, HOTSTUFF_PROTOCOL_NAME).into()
}

/// Returns the configuration value to put in
/// [`sc_network::config::FullNetworkConfiguration`].
/// For standard protocol name see [`crate::protocol_standard_name`].
pub fn hotstuff_peers_set_config<B: BlockT, N: NetworkBackend<B, <B as BlockT>::Hash>>(
    protocol_name: ProtocolName,
    metrics: sc_network::service::NotificationMetrics,
    peer_store_handle: Arc<dyn sc_network::peer_store::PeerStoreProvider>,
) -> (N::NotificationProtocolConfig, Box<dyn NotificationService>) {
    N::notification_config(
        protocol_name,
        Default::default(),
        // Notifications reach ~256kiB in size at the time of writing on Kusama and Polkadot.
        1024 * 1024,
        None,
        sc_network::config::SetConfig {
            // use mainnet protocol connections
            in_peers: 0,
            out_peers: 0,
            reserved_nodes: Vec::new(),
            non_reserved_mode: sc_network::config::NonReservedPeerMode::Deny, // non-reserved nodes message is not allowed for sc-consensus-hotstuff
        },
        metrics,
        peer_store_handle,
    )
}
