use std::{
    cmp::Ordering,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::{
    crypto::AggregateSignature,
    primitives::{ValidatorId, ViewNumber, GENESIS_VIEW},
};
use codec::{Decode, Encode};
use sp_consensus_hotstuff::{
    consensus::HOTSTUFF_CONSENSUS_ID, hash_of, AuthoritySignature, SessionIndex,
};
use sp_core::hexdisplay::AsBytesRef;
use sp_runtime::{
    traits::{Block as BlockT, NumberFor},
    Justification, Justifications, OpaqueExtrinsic,
};

const VOTE_QC_DOMAIN: &[u8] = b"sc-consensus-hotstuff/vote-qc/v1";
const TIMEOUT_TC_DOMAIN: &[u8] = b"sc-consensus-hotstuff/timeout-tc/v1";
const HIGH_QC_IN_TIMEOUT_DOMAIN: &[u8] = b"sc-consensus-hotstuff/high-qc-in-timeout/v1";

#[derive(Debug, Clone, Encode)]
pub struct VoteQcSignPayload<Hash, Number> {
    domain: Vec<u8>,
    session_index: SessionIndex,
    view: ViewNumber,
    block_hash: Hash,
    block_number: Number,
}

impl<Hash, Number> VoteQcSignPayload<Hash, Number> {
    pub fn new(
        session_index: SessionIndex,
        view: ViewNumber,
        block_hash: Hash,
        block_number: Number,
    ) -> Self {
        Self {
            domain: VOTE_QC_DOMAIN.to_vec(),
            session_index,
            view,
            block_hash,
            block_number,
        }
    }
}

#[derive(Debug, Clone, Encode)]
pub struct TimeoutTcSignPayload {
    domain: Vec<u8>,
    session_index: SessionIndex,
    view: ViewNumber,
}

impl TimeoutTcSignPayload {
    pub fn new(session_index: SessionIndex, view: ViewNumber) -> Self {
        Self {
            domain: TIMEOUT_TC_DOMAIN.to_vec(),
            session_index,
            view,
        }
    }
}

#[derive(Debug, Clone, Encode)]
pub struct HighQcInTimeoutSignPayload<Hash> {
    domain: Vec<u8>,
    timeout_session_index: SessionIndex,
    timeout_view: ViewNumber,
    high_qc_hash: Hash,
}

impl<Hash> HighQcInTimeoutSignPayload<Hash> {
    pub fn new(
        timeout_session_index: SessionIndex,
        timeout_view: ViewNumber,
        high_qc_hash: Hash,
    ) -> Self {
        Self {
            domain: HIGH_QC_IN_TIMEOUT_DOMAIN.to_vec(),
            timeout_session_index,
            timeout_view,
            high_qc_hash,
        }
    }
}

pub fn vote_qc_payload_hash<B: BlockT>(
    session_index: SessionIndex,
    view: ViewNumber,
    block_hash: B::Hash,
    block_number: NumberFor<B>,
) -> B::Hash {
    hash_of::<B>(
        VoteQcSignPayload::new(session_index, view, block_hash, block_number)
            .encode()
            .as_ref(),
    )
}

pub fn timeout_tc_payload_hash<B: BlockT>(
    session_index: SessionIndex,
    view: ViewNumber,
) -> B::Hash {
    hash_of::<B>(
        TimeoutTcSignPayload::new(session_index, view)
            .encode()
            .as_ref(),
    )
}

pub fn high_qc_in_timeout_payload_hash<B: BlockT>(
    timeout_session_index: SessionIndex,
    timeout_view: ViewNumber,
    high_qc_hash: B::Hash,
) -> B::Hash {
    hash_of::<B>(
        HighQcInTimeoutSignPayload::new(timeout_session_index, timeout_view, high_qc_hash)
            .encode()
            .as_ref(),
    )
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct QC<B: BlockT> {
    pub block_hash: B::Hash,
    pub block_number: NumberFor<B>,
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub agg_sig: AggregateSignature,
}

impl<B: BlockT> QC<B> {
    pub fn new(
        block_hash: B::Hash,
        block_number: NumberFor<B>,
        view: ViewNumber,
        session_index: SessionIndex,
        agg_sig: AggregateSignature,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            view,
            session_index,
            agg_sig,
        }
    }

    pub fn into_justification(self) -> Justification {
        (HOTSTUFF_CONSENSUS_ID, self.encode())
    }

    pub fn from_justifications(justs: Justifications) -> Option<Self> {
        let bytes = justs.get(HOTSTUFF_CONSENSUS_ID)?;
        QC::<B>::decode(&mut &bytes[..]).ok()
    }

    pub fn hash(&self) -> B::Hash {
        hash_of::<B>(self.encode().as_bytes_ref())
    }

    pub fn is_genesis(&self, genesis_hash: &B::Hash) -> bool {
        self.block_hash == *genesis_hash
            && self.block_number == Default::default()
            && self.view == GENESIS_VIEW
            && self.session_index == 0
            && self.agg_sig == AggregateSignature::default()
    }
}

impl<B: BlockT> PartialOrd for QC<B> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: BlockT> Ord for QC<B> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.view.cmp(&other.view)
    }
}

impl<B: BlockT> Default for QC<B>
where
    B::Hash: Default,
    NumberFor<B>: Default,
{
    fn default() -> Self {
        Self {
            block_hash: B::Hash::default(),
            block_number: NumberFor::<B>::default(),
            view: GENESIS_VIEW,
            session_index: 0,
            agg_sig: AggregateSignature::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct TC<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub agg_sig: AggregateSignature,
    pub _phantom: PhantomData<B>,
}

impl<B: BlockT> TC<B> {
    pub fn new(view: ViewNumber, session_index: SessionIndex, agg_sig: AggregateSignature) -> Self {
        Self {
            view,
            session_index,
            agg_sig,
            _phantom: PhantomData,
        }
    }

    pub fn hash(&self) -> B::Hash {
        hash_of::<B>(self.encode().as_bytes_ref())
    }
}

impl<B: BlockT> PartialOrd for TC<B> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: BlockT> Ord for TC<B> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.view.cmp(&other.view)
    }
}

impl<B: BlockT> Default for TC<B> {
    fn default() -> Self {
        Self {
            view: GENESIS_VIEW,
            session_index: 0,
            agg_sig: AggregateSignature::default(),
            _phantom: PhantomData,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct AggQC<B: BlockT> {
    pub qcs: Vec<(ValidatorId, QC<B>)>,
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub agg_sig: AggregateSignature,
}

impl<B: BlockT> AggQC<B> {
    pub fn new(
        view: ViewNumber,
        session_index: SessionIndex,
        qcs: Vec<(ValidatorId, QC<B>)>,
        agg_sig: AggregateSignature,
    ) -> Self {
        Self {
            qcs,
            view,
            session_index,
            agg_sig,
        }
    }

    pub fn high_qc(&self) -> Option<&QC<B>> {
        self.qcs.iter().map(|(_, qc)| qc).max_by_key(|qc| qc.view)
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct Proposal<B: BlockT> {
    pub core: ProposalCore<B>,
    pub leader_sig: Option<AuthoritySignature>,
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct ProposalCore<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub payload: Payload<B>,

    pub qc: QC<B>,
    pub tc: Option<TC<B>>,
    pub agg_qc: Option<AggQC<B>>,

    pub leader_id: ValidatorId,
    pub validator_ids_hash: B::Hash,
}

impl<B: BlockT> Deref for Proposal<B> {
    type Target = ProposalCore<B>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<B: BlockT> DerefMut for Proposal<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl<B: BlockT> Proposal<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        qc: QC<B>,
        tc: Option<TC<B>>,
        agg_qc: Option<AggQC<B>>,
        view: ViewNumber,
        session_index: SessionIndex,
        leader_id: ValidatorId,
        validator_ids_hash: B::Hash,
        block_number: NumberFor<B>,
        extrinsics: Vec<OpaqueExtrinsic>,
    ) -> Self {
        Self {
            core: ProposalCore {
                view,
                session_index,
                qc,
                tc,
                agg_qc,
                leader_id,
                validator_ids_hash,
                payload: Payload::<B> {
                    block_number,
                    extrinsics,
                },
            },
            leader_sig: None,
        }
    }

    pub fn set_leader_sig(&mut self, sig: AuthoritySignature) {
        self.leader_sig = Some(sig);
    }

    pub fn parent_hash(&self) -> &B::Hash {
        &self.qc.block_hash
    }

    pub fn parent_number(&self) -> &NumberFor<B> {
        &self.qc.block_number
    }

    pub fn extrinsics(&self) -> Vec<OpaqueExtrinsic> {
        self.payload.extrinsics.clone()
    }

    pub fn new_view(&self) -> NewView<B> {
        NewView::new(
            self.view,
            self.session_index,
            Some(self.qc.clone()),
            self.tc.clone(),
            self.agg_qc.clone(),
        )
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct Payload<B: BlockT> {
    // block_number must be parent_block.number + 1
    pub block_number: NumberFor<B>,
    pub extrinsics: Vec<OpaqueExtrinsic>,
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct Vote<B: BlockT> {
    // this is block hash calculated by authorities, not proposal hash
    pub block_hash: B::Hash,
    pub block_number: NumberFor<B>,
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub follower_id: ValidatorId,
    pub partial_sig: Option<AggregateSignature>,
}

impl<B: BlockT> Vote<B> {
    pub fn new(
        block_hash: B::Hash,
        block_number: NumberFor<B>,
        view: ViewNumber,
        session_index: SessionIndex,
        follower_id: ValidatorId,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            view,
            session_index,
            follower_id,
            partial_sig: None,
        }
    }

    pub fn set_partial_sig(&mut self, sig: AggregateSignature) {
        self.partial_sig = Some(sig)
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct NewView<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub qc: Option<QC<B>>,
    pub tc: Option<TC<B>>,
    pub agg_qc: Option<AggQC<B>>,
}

impl<B: BlockT> NewView<B> {
    pub fn new(
        view: ViewNumber,
        session_index: SessionIndex,
        qc: Option<QC<B>>,
        tc: Option<TC<B>>,
        agg_qc: Option<AggQC<B>>,
    ) -> Self {
        Self {
            view,
            session_index,
            qc,
            tc,
            agg_qc,
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct Timeout<B: BlockT> {
    pub follower_id: ValidatorId,
    pub view: ViewNumber,
    pub view_sig: Option<AggregateSignature>,
    pub session_index: SessionIndex,
    /// local high qc is for fast hotstuff agg qc generation
    pub local_high_qc: Option<QC<B>>,
    pub local_high_qc_sig: Option<AggregateSignature>,
    /// local high tc is for liveness saving when all the validators restart
    /// Broadcast timeout messages include this evidence to synchronize views.
    pub local_high_tc: Option<TC<B>>,
    pub local_high_tc_sig: Option<AggregateSignature>,
}

impl<B: BlockT> Timeout<B> {
    pub fn new(
        follower_id: ValidatorId,
        view: ViewNumber,
        session_index: SessionIndex,
        local_high_qc: Option<QC<B>>,
    ) -> Self {
        Self {
            follower_id,
            view,
            view_sig: None,
            session_index,
            local_high_qc,
            local_high_qc_sig: None,
            local_high_tc: None,
            local_high_tc_sig: None,
        }
    }

    pub fn set_view_sig(&mut self, sig: AggregateSignature) {
        self.view_sig = Some(sig);
    }

    pub fn set_local_high_qc_sig(&mut self, sig: AggregateSignature) {
        self.local_high_qc_sig = Some(sig);
    }

    pub fn set_local_high_tc(&mut self, tc: Option<TC<B>>) {
        self.local_high_tc = tc;
    }

    pub fn set_local_high_tc_sig(&mut self, sig: AggregateSignature) {
        self.local_high_tc_sig = Some(sig);
    }

    #[allow(unused)]
    pub fn with_tc_only(&self) -> Self {
        Self {
            follower_id: self.follower_id.clone(),
            view: self.view,
            view_sig: self.view_sig.clone(),
            session_index: self.session_index,
            local_high_qc: None,
            local_high_qc_sig: None,
            local_high_tc: None,
            local_high_tc_sig: None,
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub enum ConsensusMessage<B: BlockT> {
    Proposal(Proposal<B>),
    Vote(Vote<B>),
    Timeout(Timeout<B>),
    NewView(NewView<B>),
}

/// A collection of certificates for simple use
#[derive(Clone, Debug)]
pub struct SyncInfo<B: BlockT> {
    pub qc: Option<QC<B>>,
    pub tc: Option<TC<B>>,
    pub agg_qc: Option<AggQC<B>>,
}

impl<B: BlockT> SyncInfo<B> {
    pub fn new() -> Self {
        Self {
            qc: None,
            tc: None,
            agg_qc: None,
        }
    }

    /// Set QC and return the updated value for chaining.
    pub fn with_qc(mut self, qc: QC<B>) -> Self {
        self.qc = Some(qc);
        self
    }

    /// Set TC and return the updated value for chaining.
    pub fn with_tc(mut self, tc: TC<B>) -> Self {
        self.tc = Some(tc);
        self
    }

    /// Set AggQC and return the updated value for chaining.
    pub fn with_agg_qc(mut self, agg_qc: AggQC<B>) -> Self {
        self.agg_qc = Some(agg_qc);
        self
    }

    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.qc.is_none() && self.tc.is_none() && self.agg_qc.is_none()
    }
}

#[derive(Debug, Clone)]
pub enum ConsensusOp<B: BlockT> {
    /// trigger propose action of proposer
    Propose(ProposeParams<B>),
    /// trigger new_view action of proposer
    NewView(NewViewParams<B>),
    /// trigger local timeout action of pacemaker
    Timeout(TimeoutParams<B>),
}

#[derive(Debug, Clone)]
pub struct ProposeParams<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub leader_id: ValidatorId,
    pub validator_ids_hash: B::Hash,
    pub sync_info: SyncInfo<B>,
    /// Must broadcast a proposal even there's no extrinsics
    pub force_propose: bool,
}

#[derive(Debug, Clone)]
pub struct NewViewParams<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub leader_id: ValidatorId,
    pub sync_info: SyncInfo<B>,
}

#[derive(Debug, Clone)]
pub struct TimeoutParams<B: BlockT> {
    pub view: ViewNumber,
    pub session_index: SessionIndex,
    pub local_id: ValidatorId,
    pub high_qc: QC<B>,
    pub high_tc_opt: Option<TC<B>>,
}
