use codec::Encode;
use sp_consensus_hotstuff::SessionIndex;
use sp_core::hexdisplay::AsBytesRef;
use sp_runtime::traits::Block as BlockT;

use crate::{
    crypto::{AggregateSignature, Crypto},
    error::{HotstuffError, HotstuffResult},
    messages::Proposal,
    primitives::{ValidatorId, ViewNumber},
    session_info_provider::{SessionAuthorityProvider, SessionInfoService},
    state::{LeaderProvider, StateService},
};

const LOG_TARGET: &str = "sc-consensus-hotstuff::leader-validator";

/// Trigger that caused the leader election before
/// Different triggers result in different leader election strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderElectionTrigger {
    /// Leader was elected while collecting votes (happy path)
    /// - Uses pre-commit state for leader calculation(because new QC will cause a new commit)
    /// - May adjust session index for first block of new session
    Vote,
    /// Leader was elected when timeout happened (unhappy path)
    /// - Uses current committed state for leader calculation
    /// - Uses proposal's session index directly
    Timeout,
}

/// Context for leader election verification
/// Contains the calculated state at the time of leader election
/// Use `LeaderElectionContextBuilder` to construct this.
pub struct LeaderElectionContext {
    /// The trigger that caused this leader election
    trigger: LeaderElectionTrigger,
    /// The session index that was used for leader election (already calculated)
    election_session: SessionIndex,
}

impl LeaderElectionContext {
    /// Get the session index that was used for leader election
    pub fn election_session(&self) -> SessionIndex {
        self.election_session
    }

    /// Whether to use pre-commit state for leader calculation
    ///
    /// Strategy:
    /// - Vote: use pre-commit state (state before the latest commit)
    /// - Timeout: use current committed state
    pub fn use_pre_commit_state(&self) -> bool {
        matches!(self.trigger, LeaderElectionTrigger::Vote)
    }

    /// Get the trigger type
    pub fn trigger(&self) -> LeaderElectionTrigger {
        self.trigger
    }
}

/// Builder for constructing LeaderElectionContext
/// Separates construction parameters from the final context state
pub struct LeaderElectionContextBuilder {
    proposal_session: SessionIndex,
    is_first_block_of_session: bool,
    has_timeout_cert: bool,
}

impl LeaderElectionContextBuilder {
    /// Create a new builder with the required parameters
    pub fn new(
        proposal_session: SessionIndex,
        is_first_block_of_session: bool,
        has_timeout_cert: bool,
    ) -> Self {
        Self {
            proposal_session,
            is_first_block_of_session,
            has_timeout_cert,
        }
    }

    /// Build the LeaderElectionContext by calculating the election state
    pub fn build(self) -> LeaderElectionContext {
        // Determine the trigger based on whether timeout certificate exists
        let trigger = if self.has_timeout_cert {
            LeaderElectionTrigger::Timeout
        } else {
            LeaderElectionTrigger::Vote
        };

        // Calculate the session that was used for leader election
        // Strategy:
        // - Vote trigger + first block of session: leader elected in previous session
        // - All other cases: use proposal's session
        let election_session = match trigger {
            LeaderElectionTrigger::Vote if self.is_first_block_of_session => {
                // First block of new session on happy path: leader was elected in previous session
                self.proposal_session.saturating_sub(1)
            }
            _ => self.proposal_session,
        };

        LeaderElectionContext {
            trigger,
            election_session,
        }
    }
}

/// Leader validator that encapsulates leader verification logic
/// Separates the concern of leader validation from the main consensus flow
pub struct LeaderValidator<'a, B, CR>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash>,
{
    state_service: &'a StateService<B>,
    session_info_service: &'a SessionInfoService<B>,
    crypto: &'a CR,
}

impl<'a, B, CR> LeaderValidator<'a, B, CR>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash>,
{
    /// Create a new leader validator with references to required services
    pub fn new(
        state_service: &'a StateService<B>,
        session_info_service: &'a SessionInfoService<B>,
        crypto: &'a CR,
    ) -> Self {
        Self {
            state_service,
            session_info_service,
            crypto,
        }
    }

    /// Verify that the proposal's leader matches the expected leader
    ///
    /// This function performs two checks:
    /// 1. Leader identity: verifies the proposal came from the correct leader
    /// 2. Leader signature: verifies the leader's cryptographic signature
    ///
    /// # Arguments
    /// * `proposal` - The proposal to verify
    /// * `election_ctx` - Context about the leader election state
    pub async fn verify_proposal_leader(
        &self,
        proposal: &Proposal<B>,
        election_ctx: &LeaderElectionContext,
    ) -> HotstuffResult<()> {
        let actual_leader_id = proposal.leader_id.clone();

        // Calculate expected leader based on election context strategy
        let expected_leader_id = self
            .calculate_expected_leader(proposal.view, election_ctx)
            .await;

        // Verify leader identity
        self.verify_leader_identity(
            proposal.view,
            &expected_leader_id,
            &actual_leader_id,
            election_ctx,
        )?;

        // Verify leader's cryptographic signature
        self.verify_leader_signature(proposal, &actual_leader_id)
            .await
    }

    /// Calculate the expected leader based on election context
    /// Uses different strategies for Vote and Timeout triggers
    async fn calculate_expected_leader(
        &self,
        view: ViewNumber,
        election_ctx: &LeaderElectionContext,
    ) -> ValidatorId {
        let election_session = election_ctx.election_session();

        if election_ctx.use_pre_commit_state() {
            // Vote trigger: use pre-commit state
            self.state_service
                .get_leader_before_commit(view, election_session)
                .await
        } else {
            // Timeout trigger: use current committed state
            self.state_service.get_leader(view, election_session).await
        }
    }

    /// Verify that the actual leader matches the expected leader
    fn verify_leader_identity(
        &self,
        view: ViewNumber,
        expected_leader_id: &ValidatorId,
        actual_leader_id: &ValidatorId,
        election_ctx: &LeaderElectionContext,
    ) -> HotstuffResult<()> {
        if actual_leader_id != expected_leader_id {
            log::warn!(
                target: LOG_TARGET,
                "proposal was not proposed by the expected leader, view: {}, trigger: {:?}, election_session: {}, expected: {}, actual: {}",
                view,
                election_ctx.trigger(),
                election_ctx.election_session(),
                expected_leader_id,
                actual_leader_id,
            );
            return Err(HotstuffError::UnexpectedLeader(
                expected_leader_id.clone(),
                actual_leader_id.clone(),
            ));
        }
        Ok(())
    }

    /// Verify the leader's cryptographic signature
    async fn verify_leader_signature(
        &self,
        proposal: &Proposal<B>,
        leader_id: &ValidatorId,
    ) -> HotstuffResult<()> {
        // Note: We use proposal.session_index (not election_session) to get the authority_id
        // because the signature verification must use the authority key from the session
        // when the proposal was actually created
        let leader_authority_id = self
            .session_info_service
            .get_authority_id(proposal.session_index, leader_id)
            .await
            .ok_or_else(|| HotstuffError::Other("Failed to get leader authority id".to_string()))?;

        self.crypto
            .authority_verify(
                proposal
                    .leader_sig
                    .as_ref()
                    .ok_or_else(|| HotstuffError::Other("Missing leader signature".to_string()))?,
                proposal.core.encode().as_bytes_ref(),
                &leader_authority_id,
            )
            .await
            .map_err(|_| HotstuffError::InvalidSignature(proposal.view))
    }
}
