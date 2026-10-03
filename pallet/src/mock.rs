use crate as pallet_hotstuff;
use crate::session::{AuthoritySessionHandler, BlsSessionHandler, HotstuffSessionManager};
use frame_support::{
    derive_impl, parameter_types,
    sp_runtime::BoundToRuntimeAppPublic,
    traits::{ConstU32, ConstU64, Hooks, OneSessionHandler},
};
use pallet_balances as balances;
use pallet_session as session;
use sp_consensus_hotstuff::{
    AuthorityDiscoveryId, AuthorityId, BlsProofOfPossessionBytes, BlsPublicBytes,
};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, ConvertInto, IdentityLookup},
    BuildStorage,
};
use sp_std::marker::PhantomData;

type Block = frame_system::mocking::MockBlock<Test>;

type MockSessionKeys = sp_consensus_hotstuff::SessionKeys;

/// Trivial `OneSessionHandler` for `AuthorityDiscoveryId`, so the `SessionHandler` tuple
/// mirrors the runtime's 3-handler shape without pulling in `pallet-authority-discovery`.
pub struct DummyAuthDiscHandler<T>(PhantomData<T>);

impl<T> BoundToRuntimeAppPublic for DummyAuthDiscHandler<T> {
    type Public = AuthorityDiscoveryId;
}

impl<T: pallet_hotstuff::Config> OneSessionHandler<T::AccountId> for DummyAuthDiscHandler<T> {
    type Key = AuthorityDiscoveryId;

    fn on_genesis_session<'a, I>(_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, AuthorityDiscoveryId)>,
        T::AccountId: 'a,
    {
    }

    fn on_new_session<'a, I>(_changed: bool, _: I, _queued_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, AuthorityDiscoveryId)>,
        T::AccountId: 'a,
    {
    }

    fn on_disabled(_validator_index: u32) {}
}

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: balances,
        Session: session,
        Hotstuff: pallet_hotstuff,
    }
);

parameter_types! {
    pub const SessionLength: u64 = 4;
    pub const Offset: u64 = 0;
    pub const ExistentialDeposit: u64 = 1;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountData = balances::AccountData<u64>;
}

impl balances::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Balance = u64;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ConstU32<0>;
    type MaxReserves = ConstU32<0>;
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type DoneSlashHandler = ();
}

impl session::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = u64;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = session::PeriodicSessions<SessionLength, Offset>;
    type NextSessionRotation = session::PeriodicSessions<SessionLength, Offset>;
    type SessionManager = HotstuffSessionManager<Test>;
    type SessionHandler = (
        AuthoritySessionHandler<Test>,
        BlsSessionHandler<Test>,
        DummyAuthDiscHandler<Test>,
    );
    type Keys = MockSessionKeys;
    type WeightInfo = ();
    type DisablingStrategy = ();
    type Currency = Balances;
    type KeyDeposit = ConstU64<0>;
}

impl pallet_hotstuff::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxAuthorities = ConstU32<16>;
    type DefaultForceProposeIntervalMs = ConstU64<300>;
}

/// Build an `AuthorityId` (ed25519 app public) from a deterministic 32-byte seed.
pub fn authority_id(b: u8) -> AuthorityId {
    use codec::Decode;
    AuthorityId::decode(&mut &[b; 32][..]).expect("32 bytes decodes to ed25519 public")
}

/// Build an `AuthorityDiscoveryId` (sr25519 app public) from a deterministic 32-byte seed.
pub fn discovery_id(b: u8) -> AuthorityDiscoveryId {
    use codec::Decode;
    AuthorityDiscoveryId::decode(&mut &[b; 32][..]).expect("32 bytes decodes to sr25519 public")
}

pub fn genesis_authority_tuple(
    id: u64,
) -> (
    u64,
    AuthorityId,
    BlsPublicBytes,
    BlsProofOfPossessionBytes,
    AuthorityDiscoveryId,
) {
    let (bls_pk, bls_pop) = bls_material(id);
    (
        id,
        authority_id(id as u8),
        bls_pk,
        bls_pop,
        discovery_id(id as u8),
    )
}

fn bls_material(id: u64) -> (BlsPublicBytes, BlsProofOfPossessionBytes) {
    use sc_consensus_hotstuff_bls::{pop_prove, PrivateKey};

    let private_key = PrivateKey::new([id as u8; 32]);
    let public_key = private_key.public_key();
    let pop = pop_prove(&private_key);
    (
        public_key.try_into().expect("valid BLS public key"),
        pop.try_into().expect("valid BLS proof of possession"),
    )
}

/// Deterministic session keys for validator `id`.
pub fn session_keys(id: u64) -> MockSessionKeys {
    let b = id as u8;
    MockSessionKeys {
        auth: authority_id(b),
        bls_pk: bls_material(id).0,
        auth_disc: discovery_id(b),
    }
}

/// Genesis with initial authorities `1, 2` and session keys registered for an extra
/// validator `3` (so a real authority-set change can be induced via `add_queued_validator`).
pub fn new_test_ext() -> sp_io::TestExternalities {
    let initial: Vec<u64> = vec![1, 2];
    let extra: Vec<u64> = vec![3];
    let all: Vec<u64> = initial.iter().chain(extra.iter()).cloned().collect();

    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    balances::GenesisConfig::<Test> {
        balances: all.iter().map(|id| (*id, 1_000u64)).collect(),
        dev_accounts: None,
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    pallet_hotstuff::GenesisConfig::<Test> {
        initial_authorities: initial
            .iter()
            .map(|id| genesis_authority_tuple(*id))
            .collect(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    // Initial validators must match Hotstuff genesis authorities. Candidates register after genesis
    // so their key ownership check follows the same path used by a real validator join.
    session::GenesisConfig::<Test> {
        keys: initial
            .iter()
            .map(|id| (*id, *id, session_keys(*id)))
            .collect(),
        non_authority_keys: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| {
        for id in extra {
            frame_support::assert_ok!(Session::set_keys(
                RuntimeOrigin::signed(id),
                session_keys(id),
                codec::Encode::encode(&sp_consensus_hotstuff::SessionKeysProof::V1 {
                    bls_pop: bls_material(id).1
                }),
            ));
        }
    });
    ext
}

/// Run hooks for a single block `b` and return its finalized header digest, so emitted
/// `ConsensusLog` items can be decoded. Assumes block `b-1` is already finalized (or `b == 1`).
pub fn step_block(b: u64) -> sp_runtime::Digest {
    System::reset_events();
    System::initialize(&b, &System::parent_hash(), &Default::default());
    Session::on_initialize(b);
    Hotstuff::on_initialize(b);
    Hotstuff::on_finalize(b);
    Session::on_finalize(b);
    let header = System::finalize();
    header.digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Decode;
    use frame_support::{assert_noop, assert_ok};
    use sp_consensus_hotstuff::{
        consensus::{ConsensusLog, HOTSTUFF_CONSENSUS_ID},
        hash_authority_set, SessionIndex,
    };
    use sp_runtime::DigestItem;

    /// Decode any `NextAuthoritySet` consensus digests present in `digest`.
    fn next_authority_set_logs(digest: &sp_runtime::Digest) -> Vec<(SessionIndex, [u8; 32])> {
        digest
            .logs
            .iter()
            .filter_map(|item| match item {
                DigestItem::Consensus(id, data) if *id == HOTSTUFF_CONSENSUS_ID => {
                    match ConsensusLog::decode(&mut &data[..]).ok()? {
                        ConsensusLog::NextAuthoritySet {
                            next_session_index,
                            authority_set_hash,
                        } => Some((next_session_index, authority_set_hash)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn validator_without_registered_session_keys_cannot_be_queued() {
        new_test_ext().execute_with(|| {
            assert_noop!(
                Hotstuff::add_queued_validator(RuntimeOrigin::root(), 4),
                pallet_hotstuff::Error::<Test>::ValidatorKeysNotRegistered,
            );
        });
    }

    #[test]
    fn genesis_rejects_invalid_bls_pop() {
        let mut invalid = genesis_authority_tuple(1);
        invalid.3 = genesis_authority_tuple(2).3;

        let result = std::panic::catch_unwind(|| {
            let mut storage = frame_system::GenesisConfig::<Test>::default()
                .build_storage()
                .unwrap();
            pallet_hotstuff::GenesisConfig::<Test> {
                initial_authorities: vec![invalid],
            }
            .assimilate_storage(&mut storage)
            .unwrap();
        });
        assert!(result.is_err());
    }

    /// True if `digest` contains a `ValidatorChange` consensus log.
    fn has_validator_change(digest: &sp_runtime::Digest) -> bool {
        digest.logs.iter().any(|item| match item {
            DigestItem::Consensus(id, data) if *id == HOTSTUFF_CONSENSUS_ID => {
                matches!(
                    ConsensusLog::decode(&mut &data[..]),
                    Ok(ConsensusLog::ValidatorChange(_))
                )
            }
            _ => false,
        })
    }

    fn hash_authorities() -> [u8; 32] {
        hash_authority_set::<u64>(&Hotstuff::authorities())
    }

    fn hash_next_authorities() -> [u8; 32] {
        hash_authority_set::<u64>(&Hotstuff::next_authorities())
    }

    #[derive(Debug, Clone)]
    struct Record {
        block: u64,
        cur_index: SessionIndex,
        is_boundary: bool,
        hash_auth: [u8; 32],
        hash_next: [u8; 32],
        /// hash(NextAuthorities) as observed at the *previous* block (before this block's hooks).
        #[allow(dead_code)]
        prev_hash_next: [u8; 32],
        emitted: Option<(SessionIndex, [u8; 32])>,
    }

    /// Drive the mock across several session boundaries, inducing a real authority-set change
    /// partway through, recording per-block pipeline + emission state. Then assert the Part C
    /// invariants.
    #[test]
    fn spike_emits_next_authority_set_at_first_non_boundary_block() {
        new_test_ext().execute_with(|| {
            // SessionLength = 4, Offset = 0 -> boundaries at blocks 4, 8, 12, ...
            const LAST_BLOCK: u64 = 14;
            // Induce a real change: queue validator 3 to be added. Apply it before the
            // boundary at block 8 rotates so it becomes a *queued* (NextAuthorities) member
            // and later the active set.
            const ADD_AT_BLOCK: u64 = 5;

            let mut records: Vec<Record> = Vec::new();
            let mut prev_index = Hotstuff::current_session_index();
            let mut prev_hash_next = hash_next_authorities();

            for b in 1..=LAST_BLOCK {
                if b == ADD_AT_BLOCK {
                    assert_ok!(Hotstuff::add_queued_validator(RuntimeOrigin::root(), 3));
                }

                let digest = step_block(b);

                let cur_index = Hotstuff::current_session_index();
                let is_boundary = cur_index != prev_index;
                let hash_auth = hash_authorities();
                let hash_next = hash_next_authorities();
                let emitted = next_authority_set_logs(&digest);
                assert!(
                    emitted.len() <= 1,
                    "at most one NextAuthoritySet per block, block #{}",
                    b
                );
                assert!(
                    !has_validator_change(&digest),
                    "no ValidatorChange digest must be emitted, block #{}",
                    b
                );

                // Pipeline invariant (1a): a boundary block is exactly where the rotation
                // happened in on_initialize — the set that was `NextAuthorities` at the
                // previous block becomes the active `Authorities` at this block.
                if is_boundary {
                    assert_eq!(
                        hash_auth, prev_hash_next,
                        "boundary block #{}: Authorities must equal the previous block's \
                         NextAuthorities (rotation happened in on_initialize)",
                        b
                    );
                }

                records.push(Record {
                    block: b,
                    cur_index,
                    is_boundary,
                    hash_auth,
                    hash_next,
                    prev_hash_next,
                    emitted: emitted.first().copied(),
                });

                prev_index = cur_index;
                prev_hash_next = hash_next;
            }

            // Print the per-block recording table for sanity-checking the pipeline.
            log::info!(target: "runtime::sc-consensus-hotstuff", "=== spike per-block table ===");
            for r in &records {
                log::info!(
                    target: "runtime::sc-consensus-hotstuff",
                    "block={:>2} cur_idx={} boundary={:<5} hash(auth)={:02x?} hash(next)={:02x?} emitted={:?}",
                    r.block, r.cur_index, r.is_boundary, &r.hash_auth[..4], &r.hash_next[..4], r.emitted,
                );
            }

            // ---- Pipeline invariant (1b): first non-boundary block after a boundary ----
            // session index is stable, and NextAuthorities holds the upcoming (next session's)
            // set, i.e. the set that becomes active at the *next* boundary.
            for i in 1..records.len() {
                if records[i - 1].is_boundary && !records[i].is_boundary {
                    assert_eq!(
                        records[i].cur_index,
                        records[i - 1].cur_index,
                        "first non-boundary block #{}: session index stable",
                        records[i].block
                    );
                    if let Some(next_boundary) =
                        records.iter().find(|r| r.block > records[i].block && r.is_boundary)
                    {
                        assert_eq!(
                            records[i].hash_next, next_boundary.hash_auth,
                            "first non-boundary block #{}: NextAuthorities must hold the set that \
                             becomes Authorities at the next boundary (block #{})",
                            records[i].block, next_boundary.block
                        );
                    }
                }
            }

            // ---- Emission correctness (2) ----
            let emitting: Vec<&Record> =
                records.iter().filter(|r| r.emitted.is_some()).collect();

            // Exactly one emission for the single induced change.
            assert_eq!(
                emitting.len(),
                1,
                "exactly one NextAuthoritySet for the single induced change; got {:?}",
                emitting.iter().map(|r| r.block).collect::<Vec<_>>()
            );

            let rec = emitting[0];
            let (emitted_idx, emitted_hash) = rec.emitted.unwrap();

            // Emitted at a non-boundary block.
            assert!(
                !rec.is_boundary,
                "emission must NOT be at a boundary block (was #{})",
                rec.block
            );
            // It is the *first* non-boundary block of its session: the previous block is a
            // boundary (session index just advanced) or genesis-aligned. Find the boundary
            // that started this session.
            let idx = records.iter().position(|r| r.block == rec.block).unwrap();
            assert!(idx > 0, "emission cannot be at the very first block");
            assert!(
                records[idx - 1].is_boundary,
                "emission must be at the FIRST non-boundary block of its session (block #{} \
                 should be preceded by a boundary)",
                rec.block
            );

            // next_session_index == CurrentSessionIndex + 1
            assert_eq!(
                emitted_idx,
                rec.cur_index + 1,
                "next_session_index must equal CurrentSessionIndex + 1"
            );
            // authority_set_hash == hash(NextAuthorities) at emission block
            assert_eq!(
                emitted_hash, rec.hash_next,
                "emitted hash must equal hash(NextAuthorities) at the emission block"
            );

            // The emitted hash equals hash(Authorities) at the following boundary (the
            // announced set really becomes the next active signer set).
            let next_boundary = records
                .iter()
                .find(|r| r.block > rec.block && r.is_boundary)
                .expect("there must be a boundary after the emission within the run");
            assert_eq!(
                emitted_hash, next_boundary.hash_auth,
                "announced set must become Authorities at the next boundary (block #{})",
                next_boundary.block
            );

            // ---- Emission correctness: not emitted when NextAuthorities == Authorities ----
            for r in &records {
                if r.hash_auth == r.hash_next {
                    assert!(
                        r.emitted.is_none(),
                        "block #{}: must NOT emit when NextAuthorities == Authorities",
                        r.block
                    );
                }
            }
        });
    }
}
