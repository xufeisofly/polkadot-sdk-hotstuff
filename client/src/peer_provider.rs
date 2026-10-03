use sc_authority_discovery::Service as AuthorityDiscoveryService;
use sc_network::{multiaddr::Protocol, Multiaddr, PeerId};
use sp_consensus_hotstuff::{AuthorityDiscoveryId, SessionIndex};
use sp_runtime::traits::Block as BlockT;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::network::{HotstuffNetworkSender, Network};
use crate::primitives::AuthoritySet;
use crate::session_info_provider::{SessionAuthorityProvider, SessionInfoService};

#[allow(unused)]
const LOG_TARGET: &str = "sc-consensus-hotstuff::peer_provider";

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub multiaddr: Multiaddr,
}

/// Messages sent from PeerProviderService to PeerProviderWorker
enum ServiceToWorkerMsg {
    GetPeerInfo {
        auth_disc_id: AuthorityDiscoveryId,
        session_index: SessionIndex,
        response: oneshot::Sender<Option<PeerInfo>>,
    },
    GetPeerInfosWithSelf {
        authorities: AuthoritySet,
        session_index: SessionIndex,
        response: oneshot::Sender<Vec<PeerInfo>>,
    },
}

/// Service handle for peer provider operations
#[derive(Clone)]
pub struct PeerProviderService {
    to_worker: mpsc::Sender<ServiceToWorkerMsg>,
}

impl PeerProviderService {
    pub async fn get_peer_info(
        &self,
        auth_disc_id: &AuthorityDiscoveryId,
        session_index: SessionIndex,
    ) -> Option<PeerInfo> {
        let (response_tx, response_rx) = oneshot::channel();
        let msg = ServiceToWorkerMsg::GetPeerInfo {
            auth_disc_id: auth_disc_id.clone(),
            session_index,
            response: response_tx,
        };

        if let Err(e) = self.to_worker.send(msg).await {
            log::error!(
                target: LOG_TARGET,
                "Failed to send get_peer_info message: {}",
                e
            );
            return None;
        }

        response_rx.await.unwrap_or(None)
    }

    pub async fn get_peer_infos_with_self(
        &self,
        authorities: &AuthoritySet,
        session_index: SessionIndex,
    ) -> Vec<PeerInfo> {
        let (response_tx, response_rx) = oneshot::channel();
        let msg = ServiceToWorkerMsg::GetPeerInfosWithSelf {
            authorities: authorities.clone(),
            session_index,
            response: response_tx,
        };

        if let Err(e) = self.to_worker.send(msg).await {
            log::error!(
                target: LOG_TARGET,
                "Failed to send get_peer_infos_with_self message: {}",
                e
            );
            return Vec::new();
        }

        response_rx.await.unwrap_or_else(|_| Vec::new())
    }
}

/// Worker that handles peer provider operations
pub struct PeerProviderWorker<B, N>
where
    B: BlockT,
    N: Network<B> + Sync + 'static,
{
    from_service: mpsc::Receiver<ServiceToWorkerMsg>,
    auth_disc: AuthorityDiscoveryService,
    session_info_service: Arc<SessionInfoService<B>>,
    network: HotstuffNetworkSender<B, N>,
}

impl<B, N> PeerProviderWorker<B, N>
where
    B: BlockT,
    N: Network<B> + Sync + 'static,
{
    pub fn new_with_service(
        auth_disc: AuthorityDiscoveryService,
        session_info_service: Arc<SessionInfoService<B>>,
        network: HotstuffNetworkSender<B, N>,
    ) -> (Self, PeerProviderService) {
        let (to_worker, from_service) = mpsc::channel(64);

        let worker = Self {
            from_service,
            auth_disc,
            session_info_service,
            network,
        };

        let service = PeerProviderService { to_worker };

        (worker, service)
    }

    pub async fn run(mut self) {
        loop {
            if let Some(msg) = self.from_service.recv().await {
                match msg {
                    ServiceToWorkerMsg::GetPeerInfo {
                        auth_disc_id,
                        session_index,
                        response,
                    } => {
                        let result = self
                            .handle_get_peer_info(&auth_disc_id, session_index)
                            .await;
                        let _ = response.send(result);
                    }
                    ServiceToWorkerMsg::GetPeerInfosWithSelf {
                        authorities,
                        session_index,
                        response,
                    } => {
                        let result = self
                            .handle_get_peer_infos_with_self(&authorities, session_index)
                            .await;
                        let _ = response.send(result);
                    }
                }
            }
        }
    }

    async fn handle_get_peer_info(
        &mut self,
        auth_disc_id: &AuthorityDiscoveryId,
        session_index: SessionIndex,
    ) -> Option<PeerInfo> {
        if let Some(local_auth_disc_id) = self
            .session_info_service
            .local_auth_disc_id(session_index)
            .await
        {
            if *auth_disc_id == local_auth_disc_id {
                let addr_set: HashSet<Multiaddr> =
                    self.network.listen_addresses().into_iter().collect();
                return Some(PeerInfo {
                    peer_id: self.network.local_peer_id(),
                    multiaddr: select_best_multiaddr(&addr_set)?,
                });
            }
        };

        let multiaddrs = self
            .auth_disc
            .get_addresses_by_authority_id(auth_disc_id.clone())
            .await?;
        let peer_id = extract_peer_id_from_addrs(&multiaddrs)?;
        let best_multiaddr = select_best_multiaddr(&multiaddrs)?;
        Some(PeerInfo {
            peer_id,
            multiaddr: best_multiaddr,
        })
    }

    async fn handle_get_peer_infos_with_self(
        &mut self,
        authorities: &AuthoritySet,
        session_index: SessionIndex,
    ) -> Vec<PeerInfo> {
        let mut peer_infos = Vec::new();
        for (_, _, _, auth_disc_id) in authorities.values() {
            if let Some(peer_info) = self.handle_get_peer_info(auth_disc_id, session_index).await {
                peer_infos.push(peer_info);
            }
        }
        peer_infos
    }
}

fn extract_peer_id_from_addrs(addrs: &HashSet<Multiaddr>) -> Option<PeerId> {
    for addr in addrs {
        for proto in addr.iter() {
            if let Protocol::P2p(mh) = proto {
                if let Ok(pid) = PeerId::from_multihash(mh) {
                    return Some(pid);
                }
            }
        }
    }
    None
}

fn select_best_multiaddr(addrs: &HashSet<Multiaddr>) -> Option<Multiaddr> {
    // Prefer non-loopback IPv4/TCP addresses to avoid selecting local-only
    // endpoints (e.g. 127.0.0.1) from authority-discovery on multi-node setups.
    let mut non_loopback_ip4_tcp: Vec<Multiaddr> = Vec::new();
    let mut loopback_ip4_tcp: Vec<Multiaddr> = Vec::new();
    let mut other: Vec<Multiaddr> = Vec::new();

    for addr in addrs {
        let mut ip4 = None;
        let mut has_tcp = false;

        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(v4) => ip4 = Some(v4),
                Protocol::Tcp(_) => has_tcp = true,
                _ => {}
            }
        }

        match (ip4, has_tcp) {
            (Some(v4), true) if v4.is_loopback() => loopback_ip4_tcp.push(addr.clone()),
            (Some(_), true) => non_loopback_ip4_tcp.push(addr.clone()),
            _ => other.push(addr.clone()),
        }
    }

    // Sort for deterministic selection (HashSet iteration order is nondeterministic).
    non_loopback_ip4_tcp.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    loopback_ip4_tcp.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    other.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

    non_loopback_ip4_tcp
        .into_iter()
        .next()
        .or_else(|| loopback_ip4_tcp.into_iter().next())
        .or_else(|| other.into_iter().next())
}
