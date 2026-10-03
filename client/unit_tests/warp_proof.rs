//! Unit tests for the `warp_proof` module.
//!
//! Included from `src/warp_proof.rs` via `#[path]` so the tests keep access to
//! crate-private items while living outside the production source file.

use super::*;
use crate::crypto::{AggregateSignature, ValidatorIndices};
use crate::messages::vote_qc_payload_hash;
use crate::primitives::ViewNumber;
use codec::Encode;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sc_consensus_hotstuff_bls::{PrivateKey, Serialize as _};
use sp_consensus_hotstuff::consensus::{ConsensusLog, HOTSTUFF_CONSENSUS_ID};
use sp_consensus_hotstuff::{
    hash_authority_set, AccountId, AuthorityDiscoveryId, AuthorityId, BlsPublicBytes,
};
use sp_core::crypto::AccountId32;
use sp_core::H256;
use sp_runtime::generic::{Digest, Header};
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::{DigestItem, OpaqueExtrinsic};

type TestHeader = Header<u32, BlakeTwo256>;
type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

/// A validator with a real BLS key, used to build signing sets in tests.
struct Validator {
    info: AuthorityInfo,
    sk: PrivateKey,
}

fn authority(seed: u8) -> AuthorityInfo {
    let account = AccountId32::new([seed; 32]);
    let auth_id = AuthorityId::decode(&mut &[seed; 32][..]).expect("32 bytes -> ed25519");
    let disc_id = AuthorityDiscoveryId::decode(&mut &[seed; 32][..]).expect("32 bytes -> sr25519");
    let bls = BlsPublicBytes::from([seed; 48]);
    (account, auth_id, bls, disc_id)
}

/// Build a set of `seeds.len()` validators with real BLS keys.
///
/// The `AccountId` of each validator is `[seed; 32]`, so passing **ascending** seeds means
/// the input order is already the `AccountId`-sorted order. That keeps the QC bitmap-index
/// construction trivial: a validator's position in `set` equals its position in
/// `sorted_pks(set)` (the order `verify_qc_with_validator_pks` maps bitmap bits into).
fn make_set(seeds: &[u8]) -> Vec<Validator> {
    seeds
        .iter()
        .map(|&seed| {
            // Derive each validator's BLS key deterministically from its own seed, so distinct
            // seeds always yield distinct keys (and the same seed reproduces the same key).
            // This is essential for the "QC by wrong set" test: two sets with different seeds
            // must NOT share keys, or a QC from one would verify against the other.
            let mut rng = StdRng::seed_from_u64(0x00C0_FFEE_0000 ^ seed as u64);
            let sk = PrivateKey::generate(&mut rng);
            let pk = sk.public_key();
            let bls = BlsPublicBytes::new(
                pk.as_bytes()
                    .try_into()
                    .expect("BLS public key is 48 bytes"),
            );
            let account = AccountId32::new([seed; 32]);
            let auth_id = AuthorityId::decode(&mut &[seed; 32][..]).expect("32 bytes -> ed25519");
            let disc_id =
                AuthorityDiscoveryId::decode(&mut &[seed; 32][..]).expect("32 bytes -> sr25519");
            Validator {
                info: (account, auth_id, bls, disc_id),
                sk,
            }
        })
        .collect()
}

/// Project the validators to the `AuthorityInfo` set shipped/anchored in a proof.
fn authorities(set: &[Validator]) -> Vec<AuthorityInfo> {
    set.iter().map(|v| v.info.clone()).collect()
}

/// Assert that a `verify_chain` result is `Err(InvalidProof(msg))` whose message contains
/// `needle`. (`VerifiedChain` is not `Debug`, so we cannot use `expect_err`.)
fn assert_invalid_proof(result: Result<VerifiedChain<TestBlock>, WarpError>, needle: &str) {
    match result {
        Ok(_) => panic!("expected Err(InvalidProof), got Ok"),
        Err(WarpError::InvalidProof(msg)) => assert!(
            msg.contains(needle),
            "expected error message to contain {needle:?}, got: {msg}",
        ),
        Err(other) => panic!("expected InvalidProof, got {other:?}"),
    }
}

/// Build a header at `number` with the given `parent_hash` and digest logs.
fn header(number: u32, parent_hash: H256, logs: Vec<DigestItem>) -> TestHeader {
    TestHeader {
        parent_hash,
        number,
        state_root: H256::repeat_byte(0xAA),
        // Mix `number` into the extrinsics root so distinct blocks get distinct hashes.
        extrinsics_root: H256::from_low_u64_be(0x5000 + number as u64),
        digest: Digest { logs },
    }
}

/// A `NextAuthoritySet` consensus digest item announcing `next_set` at `next_session`.
fn next_authority_set_digest(next_session: SessionIndex, next_set: &[AuthorityInfo]) -> DigestItem {
    DigestItem::Consensus(
        HOTSTUFF_CONSENSUS_ID,
        ConsensusLog::NextAuthoritySet {
            next_session_index: next_session,
            authority_set_hash: hash_authority_set(next_set),
        }
        .encode(),
    )
}

/// Build a `QC<TestBlock>` certifying `(block_hash, number)` under `signing_set`.
///
/// `signer_positions` are indices into `signing_set` **in `AccountId`-sorted order**
/// (since `make_set` is built ascending, that is just the slice order). For each signer we
/// (a) set the corresponding bit in `ValidatorIndices` and (b) sign the canonical
/// `vote_qc_payload_hash` payload; we then aggregate exactly those signatures. This mirrors
/// how a real quorum is assembled and is exactly what `verify_qc_with_validator_pks`
/// re-checks: it maps each bitmap bit into `sorted_pks(current_set)` and verifies the
/// aggregate against the same payload.
fn make_qc(
    signing_set: &[Validator],
    signer_positions: &[usize],
    session: SessionIndex,
    view: ViewNumber,
    block_hash: H256,
    number: u32,
) -> QC<TestBlock> {
    let payload = vote_qc_payload_hash::<TestBlock>(session, view, block_hash, number);

    let mut participants = ValidatorIndices::new();
    let mut sigs = Vec::with_capacity(signer_positions.len());
    for &pos in signer_positions {
        participants.add_index(pos);
        sigs.push(signing_set[pos].sk.sign(payload.as_ref()));
    }
    let agg = sc_consensus_hotstuff_bls::aggregate(&sigs).expect("aggregate signatures");
    let agg_sig = AggregateSignature::new(agg, participants);
    QC::<TestBlock>::new(block_hash, number, view, session, agg_sig)
}

/// Build a single fragment: announce header at `announce_num` (carrying the
/// `NextAuthoritySet` digest for `next_set`) committed under `current_set` via the 2-chain
/// QC(announce) and QC(child). Returns the fragment and the child header's hash (the parent
/// for whatever hop comes next).
#[allow(clippy::too_many_arguments)]
fn make_fragment(
    current_set: &[Validator],
    signer_positions: &[usize],
    session: SessionIndex,
    view: ViewNumber,
    announce_num: u32,
    announce_parent: H256,
    next_session: SessionIndex,
    next_set: &[AuthorityInfo],
) -> (WarpSyncFragment<TestBlock>, H256) {
    let announce_header = header(
        announce_num,
        announce_parent,
        vec![next_authority_set_digest(next_session, next_set)],
    );
    let announce_hash = announce_header.hash();
    let child_header = header(announce_num + 1, announce_hash, vec![]);
    let child_hash = child_header.hash();

    let qc_announce = make_qc(
        current_set,
        signer_positions,
        session,
        view,
        announce_hash,
        announce_num,
    );
    let qc_child = make_qc(
        current_set,
        signer_positions,
        session,
        view,
        child_hash,
        announce_num + 1,
    );

    let fragment = WarpSyncFragment {
        announce_header,
        child_header,
        qc_announce,
        qc_child,
        next_authorities: next_set.to_vec(),
    };
    (fragment, child_hash)
}

/// Build a target hop: target header at `target_num` committed under `final_set` via
/// QC(target) + QC(child).
fn make_target(
    final_set: &[Validator],
    signer_positions: &[usize],
    session: SessionIndex,
    view: ViewNumber,
    target_num: u32,
    target_parent: H256,
) -> WarpSyncTarget<TestBlock> {
    let target_header = header(target_num, target_parent, vec![]);
    let target_hash = target_header.hash();
    let child_header = header(target_num + 1, target_hash, vec![]);
    let child_hash = child_header.hash();

    let qc_target = make_qc(
        final_set,
        signer_positions,
        session,
        view,
        target_hash,
        target_num,
    );
    let qc_child = make_qc(
        final_set,
        signer_positions,
        session,
        view,
        child_hash,
        target_num + 1,
    );

    WarpSyncTarget {
        target_header,
        child_header,
        qc_target,
        qc_child,
    }
}

#[test]
fn sorted_pks_orders_by_validator_id() {
    // Build an out-of-order set; `sorted_pks` must order by `ValidatorId` ascending.
    let set = vec![authority(3), authority(1), authority(2)];
    let pks = sorted_pks(&set);
    let ids: Vec<AccountId> = pks.iter().map(|(id, _)| id.clone()).collect();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(ids, expected, "sorted_pks must order by ValidatorId");
    // And the projection drops to (id, bls) pairs.
    assert_eq!(pks.len(), 3);
}

#[test]
fn finished_proof_requires_target_and_partial_proof_cannot_finalize_child() {
    let set = make_set(&[1, 2, 3, 4]);
    let next_set = make_set(&[1, 2, 3, 5]);
    let (fragment, child_hash) = make_fragment(
        &set,
        &[0, 1, 2],
        0,
        10,
        10,
        H256::repeat_byte(0x11),
        1,
        &authorities(&next_set),
    );
    let mut proof = WarpSyncProof::<TestBlock> {
        fragments: vec![fragment],
        target: None,
        is_finished: false,
    };
    assert_eq!(
        proof
            .verify_chain(0, authorities(&set))
            .unwrap()
            .last_header
            .hash(),
        proof.fragments[0].announce_header.hash()
    );
    proof.is_finished = true;
    assert_invalid_proof(
        proof.verify_chain(0, authorities(&set)),
        "finished proof must have a target",
    );

    proof.target = Some(make_target(&next_set, &[0, 1, 2], 1, 20, 20, child_hash));
    let verified = proof.verify_chain(0, authorities(&set)).unwrap();
    assert_eq!(
        verified.last_header.hash(),
        proof.target.as_ref().unwrap().target_header.hash()
    );
    proof.is_finished = false;
    assert_invalid_proof(
        proof.verify_chain(0, authorities(&set)),
        "partial proof must not have one",
    );
}

/// Test 1 — full roundtrip success: anchor set_A → two fragments transitioning to set_B then
/// set_C → target under set_C. `verify_chain` is `Ok`, the end-state is set_C, and the
/// change-points list both transitions in order.
#[test]
fn verify_chain_roundtrip_success() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    // 2-of-3 quorum signs each QC; signer positions are slice positions == sorted positions.
    let signers = [0usize, 1usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let set_c = make_set(&[7, 8, 9]);
    let b_infos = authorities(&set_b);
    let c_infos = authorities(&set_c);

    // Fragment 0: announced at block 10 under set_A (session 0), ships set_B (session 1).
    let (frag0, child0_hash) = make_fragment(
        &set_a,
        &signers,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &b_infos,
    );
    // Fragment 1: announced at block 20 under set_B (session 1), ships set_C (session 2).
    let (frag1, child1_hash) =
        make_fragment(&set_b, &signers, 1, view, 20, child0_hash, 2, &c_infos);
    // Target: block 30 committed under set_C (session 2).
    let target = make_target(&set_c, &signers, 2, view, 30, child1_hash);
    let target_hash = target.target_header.hash();

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag0, frag1],
        target: Some(target),
        is_finished: true,
    };

    let verified = proof
        .verify_chain(anchor_session, authorities(&set_a))
        .expect("roundtrip proof must verify");

    assert_eq!(verified.last_session, 2, "final session is set_C's session");
    assert_eq!(verified.last_set, c_infos, "end-state set is set_C");
    assert_eq!(
        verified.last_header.hash(),
        target_hash,
        "last header is the target header",
    );
    assert_eq!(
        verified.change_points,
        vec![(1, b_infos.clone()), (2, c_infos.clone())],
        "change points list both transitions in order",
    );
}

/// Test 2 — forged next_authorities: QCs are all valid, but the shipped `next_authorities`
/// is a different set than the one whose hash is in the announce digest, so the digest-match
/// check rejects the proof.
#[test]
fn verify_chain_rejects_forged_next_authorities() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    let signers = [0usize, 1usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let set_b_infos = authorities(&set_b);

    // The announce digest commits to set_B's hash...
    let (mut frag, _child) = make_fragment(
        &set_a,
        &signers,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &set_b_infos,
    );
    // ...but we ship a *different* set (set_X). QCs are still valid; only the digest
    // recomputation must fail.
    let set_x = make_set(&[40, 50, 60]);
    frag.next_authorities = authorities(&set_x);

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag],
        target: None,
        is_finished: false,
    };

    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "hash does not match digest",
    );
}

/// Test 3 — broken 2-chain linkage: the child header's parent_hash does not equal the
/// announce header's hash. This is checked before any signature verification.
#[test]
fn verify_chain_rejects_broken_linkage() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    let signers = [0usize, 1usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let set_b_infos = authorities(&set_b);

    let (mut frag, _child) = make_fragment(
        &set_a,
        &signers,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &set_b_infos,
    );
    // Sever the linkage: child no longer extends the announce block.
    frag.child_header = header(11, H256::repeat_byte(0xEE), vec![]);

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag],
        target: None,
        is_finished: false,
    };

    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "child does not extend announce",
    );
}

/// Test 4 — QC signed by the wrong set: the fragment's QCs are produced by set_B but the
/// proof is anchored on set_A, so verifying the QC against set_A's keys fails.
#[test]
fn verify_chain_rejects_qc_by_wrong_set() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    let signers = [0usize, 1usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let set_c = make_set(&[7, 8, 9]);
    let set_c_infos = authorities(&set_c);

    // Build the fragment but have set_B (NOT the anchor set_A) sign the QCs. The headers and
    // digest are well-formed; only the signing set is wrong.
    let (frag, _child) = make_fragment(
        &set_b, // wrong signer set
        &signers,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &set_c_infos,
    );

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag],
        target: None,
        is_finished: false,
    };

    // Anchor on set_A: the QCs were made by set_B's keys, so verification fails.
    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "qc_announce verification failed",
    );
}

/// Test 5 — child QC does not certify the child header: structurally the `qc_child.block_hash`
/// points at a different block, so there is no valid 2-chain. Checked before signature
/// verification.
#[test]
fn verify_chain_rejects_child_qc_not_certifying_child() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    let signers = [0usize, 1usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let set_b_infos = authorities(&set_b);

    let (mut frag, _child) = make_fragment(
        &set_a,
        &signers,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &set_b_infos,
    );
    // Replace qc_child with one certifying some unrelated block hash/number.
    frag.qc_child = make_qc(
        &set_a,
        &signers,
        anchor_session,
        view,
        H256::repeat_byte(0x99),
        999,
    );

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag],
        target: None,
        is_finished: false,
    };

    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "qc_child does not match child header",
    );
}

/// Test 6 — sub-quorum fragment QC: the QCs are individually valid BLS aggregates but carry
/// FEWER signatures than the 2/3 quorum of the current set. Without a quorum check a single
/// validator could authenticate a forged authority-set transition, so this must be rejected.
#[test]
fn verify_chain_rejects_sub_quorum_fragment_qc() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    // set_a has 3 validators → quorum = ceil(2*3/3) = 2. Sign with only ONE validator.
    let sub_quorum = [0usize];

    let set_a = make_set(&[1, 2, 3]);
    let set_b = make_set(&[4, 5, 6]);
    let b_infos = authorities(&set_b);

    let (frag, _child) = make_fragment(
        &set_a,
        &sub_quorum,
        anchor_session,
        view,
        10,
        H256::repeat_byte(0x11),
        1,
        &b_infos,
    );

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![frag],
        target: None,
        is_finished: false,
    };

    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "quorum",
    );
}

/// Test 7 — sub-quorum target QC: the target's QCs are valid BLS aggregates but below quorum.
/// Must be rejected for the same reason (a sub-quorum minority could forge the warp target).
#[test]
fn verify_chain_rejects_sub_quorum_target_qc() {
    let anchor_session: SessionIndex = 0;
    let view: ViewNumber = 7;
    let sub_quorum = [0usize];

    // No fragments: the target is verified directly against the anchor set (3 validators).
    let set_a = make_set(&[1, 2, 3]);
    let target = make_target(
        &set_a,
        &sub_quorum,
        anchor_session,
        view,
        30,
        H256::repeat_byte(0x11),
    );

    let proof = WarpSyncProof::<TestBlock> {
        fragments: vec![],
        target: Some(target),
        is_finished: true,
    };

    assert_invalid_proof(
        proof.verify_chain(anchor_session, authorities(&set_a)),
        "quorum",
    );
}
