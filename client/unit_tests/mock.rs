//! Mock implementations for testing sc-consensus-hotstuff components

use crate::primitives::ValidatorId;
use crate::session_info_provider::{ServicetoWorkerMsg, SessionInfoService};
use codec::Encode;
use sc_consensus_hotstuff_bls::PublicKey;
use sp_consensus_hotstuff::hash_of;
use sp_runtime::traits::Block as BlockT;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

// Re-export SessionIndex for test convenience
pub use sp_consensus_hotstuff::SessionIndex;

/// Mock session state for testing
#[derive(Clone)]
pub struct MockSessionState {
    pub session_index: SessionIndex,
    pub quorum: usize,
    pub validator_ids: Vec<ValidatorId>,
    pub bls_keys: HashMap<ValidatorId, PublicKey>,
    pub local_index: usize,
}

/// Spawn a mock session info service for testing
pub fn spawn_session_info_service<B: BlockT>(
    state: Arc<MockSessionState>,
) -> (Arc<SessionInfoService<B>>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel(16);
    let service = Arc::new(SessionInfoService::new_for_test(tx));
    let worker_state = state.clone();

    let handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                ServicetoWorkerMsg::IsAuthorityForCurrentSession(sender) => {
                    let _ = sender.send(true);
                }
                ServicetoWorkerMsg::CurrentSessionIndex(sender) => {
                    let _ = sender.send(worker_state.session_index);
                }
                ServicetoWorkerMsg::HistoricalSessionIndex(sender) => {
                    let _ = sender.send(worker_state.session_index);
                }
                ServicetoWorkerMsg::GetAuthorities(_, sender) => {
                    let _ = sender.send(Default::default());
                }
                ServicetoWorkerMsg::ValidatorIdsHash(_, sender) => {
                    let hash = hash_of::<B>(worker_state.validator_ids.encode().as_ref());
                    let _ = sender.send(hash);
                }
                ServicetoWorkerMsg::LocalAuthorityId(_, sender) => {
                    let _ = sender.send(None);
                }
                ServicetoWorkerMsg::GetAuthorityId(_, _, sender) => {
                    let _ = sender.send(None);
                }
                ServicetoWorkerMsg::LocalAuthDiscId(_, sender) => {
                    let _ = sender.send(None);
                }
                ServicetoWorkerMsg::GetAuthDiscId(_, _, sender) => {
                    let _ = sender.send(None);
                }
                ServicetoWorkerMsg::LocalValidatorId(sender) => {
                    let id = worker_state.validator_ids[worker_state.local_index].clone();
                    let _ = sender.send(Some(id));
                }
                ServicetoWorkerMsg::GetBlsPublc(_, id, sender) => {
                    let _ = sender.send(worker_state.bls_keys.get(&id).cloned());
                }
                ServicetoWorkerMsg::ShouldEndSession(_, sender) => {
                    let _ = sender.send(false);
                }
                ServicetoWorkerMsg::TotalVotingPower(_, sender) => {
                    let _ = sender.send(worker_state.validator_ids.len());
                }
                ServicetoWorkerMsg::QuorumVotingPower(_, sender) => {
                    let _ = sender.send(worker_state.quorum);
                }
                ServicetoWorkerMsg::AdvanceCurrentSession(sender) => {
                    let _ = sender.send(worker_state.session_index.saturating_add(1));
                }
                ServicetoWorkerMsg::AdvanceHistoricalSession(_, sender) => {
                    let _ = sender.send(worker_state.session_index);
                }
                ServicetoWorkerMsg::SessionIndexByNumber(_, sender) => {
                    let _ = sender.send(worker_state.session_index);
                }
                ServicetoWorkerMsg::GetValidatorIds(_, sender) => {
                    let _ = sender.send(Arc::new(worker_state.validator_ids.clone()));
                }
            }
        }
    });

    (service, handle)
}
