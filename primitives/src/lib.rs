#![cfg_attr(not(feature = "std"), no_std)]
//! Runtime-independent types and runtime API for Hotstuff.
use codec::Encode;
use sp_runtime::{
    traits::{Block, Hash as HashT, Header as HeaderT},
    KeyTypeId,
};
pub use sp_staking::SessionIndex;
use sp_std::vec::Vec;

mod bls;
pub mod consensus;
pub use bls::{
    verify_bls_pop, BlsProofOfPossessionBytes, BlsPublicBytes, BlsSignatureBytes, SessionKeysProof,
    BLS_POP_CIPHERSUITE,
};

pub const HOTSTUFF_KEY_TYPE: KeyTypeId = KeyTypeId(*b"hots");
pub const HOTSTUFF_BLS_KEY_TYPE: KeyTypeId = KeyTypeId(*b"bls7");
pub const HOTSTUFF_AUTH_DISC_KEY_TYPE: KeyTypeId = sp_core::crypto::key_types::AUTHORITY_DISCOVERY;
mod app {
    use sp_application_crypto::{app_crypto, ed25519};
    app_crypto!(ed25519, crate::HOTSTUFF_KEY_TYPE);
}
sp_application_crypto::with_pair! { pub type AuthorityPair = app::Pair; }
pub type AuthorityId = app::Public;
pub type AuthoritySignature = app::Signature;
pub type AuthorityDiscoveryId = sp_authority_discovery::AuthorityId;
/// Stable consensus identity; runtimes may map their own account type to this ID.
pub type AccountId = sp_core::crypto::AccountId32;

pub fn hash_of<B: Block>(s: &[u8]) -> B::Hash {
    <<B::Header as HeaderT>::Hashing as HashT>::hash(s)
}

pub fn hash_of_encoded(data: &[u8]) -> [u8; 32] {
    sp_io::hashing::blake2_256(data)
}

/// Authority tuple as stored by `pallet-hotstuff` and shipped in warp-sync fragments.
pub type AuthorityTuple = (AccountId, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId);

/// Canonical hash of an authority set.
///
/// Sorts by account id (== `ValidatorId`, see runtime `configs/mod.rs:211`), then
/// SCALE-encodes and blake2-256 hashes. MUST match `BTreeMap<ValidatorId>` iteration
/// order, which is how QC validator-bitmap indices are assigned
/// (`session_info_provider.rs` `set.keys()`). The pallet emits this hash in the
/// `NextAuthoritySet` digest; the warp verifier recomputes it over the shipped set.
pub fn hash_authority_set<A>(
    set: &[(A, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId)],
) -> [u8; 32]
where
    A: Clone + Ord + codec::Encode,
{
    let mut sorted = set.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    hash_of_encoded(&sorted.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Decode;
    use sp_core::crypto::AccountId32;

    /// Build an `AuthorityId` (ed25519 app public) from a 32-byte seed.
    fn authority_id(b: u8) -> AuthorityId {
        AuthorityId::decode(&mut &[b; 32][..]).expect("32 bytes decodes to ed25519 public")
    }

    /// Build an `AuthorityDiscoveryId` (sr25519 app public) from a 32-byte seed.
    fn discovery_id(b: u8) -> AuthorityDiscoveryId {
        AuthorityDiscoveryId::decode(&mut &[b; 32][..]).expect("32 bytes decodes to sr25519 public")
    }

    fn tuple(account: u8, key: u8) -> AuthorityTuple {
        (
            AccountId32::new([account; 32]),
            authority_id(key),
            BlsPublicBytes::new([key; 48]),
            discovery_id(key),
        )
    }

    #[test]
    fn hash_is_order_independent() {
        let a = tuple(1, 10);
        let b = tuple(2, 20);
        let c = tuple(3, 30);

        let forward = [a.clone(), b.clone(), c.clone()];
        let shuffled = [c, a, b];

        assert_eq!(
            hash_authority_set(&forward),
            hash_authority_set(&shuffled),
            "the same set in a different input order must hash identically",
        );
    }

    #[test]
    fn hash_changes_with_different_member() {
        let a = tuple(1, 10);
        let b = tuple(2, 20);

        let original = [a.clone(), b.clone()];
        let changed = [a, tuple(4, 40)];

        assert_ne!(
            hash_authority_set(&original),
            hash_authority_set(&changed),
            "a set with a different member must hash differently",
        );
    }
}

sp_api::decl_runtime_apis! {
    pub trait HotstuffApi<BlockNumber: codec::Codec> {
        /// Get current authorities (validators) with their keys
        fn authorities() -> Vec<(AccountId, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId)>;

        /// Get next session's authorities (validators) with their keys
        fn next_authorities() -> Vec<(AccountId, AuthorityId, BlsPublicBytes, AuthorityDiscoveryId)>;

        /// Get current session index
        fn current_session_index() -> SessionIndex;

        /// Check if the session should end at the given block number.
        ///
        /// This is a passthrough to pallet-session's `ShouldEndSession::should_end_session()` trait method.
        /// Returns `true` if the given block number is the last block of current session.
        ///
        /// # Parameters
        /// - `block_number`: The block number to check
        ///
        /// # Returns
        /// - `true` if session ends at this block (session rotation will happen in next block)
        /// - `false` otherwise
        ///
        /// # Example
        /// For a session with period=100 and offset=0:
        /// - `should_end_session(99)` returns `false`
        /// - `should_end_session(100)` returns `true`  // Last block of session
        /// - `should_end_session(101)` returns `false` // First block of next session
        fn should_end_session(block_number: BlockNumber) -> bool;

        /// Get the current force-propose interval in milliseconds.
        fn force_propose_interval_ms() -> u64;

        /// Immutable periodic session schedule (period, offset), in blocks.
        fn session_schedule() -> (u32, u32);
    }
}

mod session_keys;
pub use session_keys::SessionKeys;
