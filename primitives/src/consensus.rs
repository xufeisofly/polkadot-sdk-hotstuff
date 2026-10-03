use crate::AccountId;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

use sp_runtime::ConsensusEngineId;
use sp_staking::SessionIndex;

pub const HOTSTUFF_CONSENSUS_ID: ConsensusEngineId = *b"HOTS";

/// A scheduled change of authority set.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo)]
pub struct ValidatorChange {
    pub session_index: SessionIndex,
    pub cur_validator_ids_hash: [u8; 32],
}

#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub enum ConsensusLog {
    #[codec(index = 1)]
    ValidatorChange(ValidatorChange),

    #[codec(index = 2)]
    Proposer(AccountId),

    #[codec(index = 3)]
    NextAuthoritySet {
        next_session_index: SessionIndex,
        authority_set_hash: [u8; 32],
    },
}
