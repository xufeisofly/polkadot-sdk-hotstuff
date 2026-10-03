//! Unit tests for the `block_importer` module.
//!
//! Included from `src/block_importer.rs` via `#[path]` so the tests keep access to
//! crate-private items while living outside the production source file.

use super::sync_qc_has_quorum;
use crate::{
    crypto::{AggregateSignature, ValidatorIndices},
    messages::QC,
};
use sc_consensus_hotstuff_bls::Signature;
use sp_core::H256;
use sp_runtime::{
    generic::{Block, Header},
    traits::BlakeTwo256,
    OpaqueExtrinsic,
};

type TestBlock = Block<Header<u32, BlakeTwo256>, OpaqueExtrinsic>;

fn qc_with_participants(count: usize) -> QC<TestBlock> {
    let mut participants = ValidatorIndices::new();
    for index in 0..count {
        participants.add_index(index);
    }

    QC::new(
        H256::from_low_u64_be(1),
        1u32,
        1,
        1,
        AggregateSignature::new(Signature::default(), participants),
    )
}

#[test]
fn sync_qc_quorum_requires_two_thirds_of_validator_set() {
    assert!(!sync_qc_has_quorum(&qc_with_participants(1), 3));
    assert!(sync_qc_has_quorum(&qc_with_participants(2), 3));
}

#[test]
fn sync_qc_quorum_rejects_empty_validator_set() {
    assert!(!sync_qc_has_quorum(&qc_with_participants(1), 0));
}
