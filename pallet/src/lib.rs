#![cfg_attr(not(feature = "std"), no_std)]
#![allow(deprecated)]

use frame_support::traits::StorageVersion;
use frame_support::{pallet_prelude::*, traits::Get, BoundedVec};
// use frame_system::pallet_prelude::*;
pub use pallet::*;
use pallet_session::Pallet as SessionPallet;
use sp_consensus_hotstuff::{
    hash_authority_set, verify_bls_pop, AuthorityDiscoveryId, AuthorityId,
    BlsProofOfPossessionBytes, BlsPublicBytes, SessionIndex,
};
use sp_runtime::traits::{Convert, OpaqueKeys};
use sp_std::prelude::*;
pub mod session;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod test_helpers {
    use super::*;

    // Minimal AccountId type for tests
    type A = u64;

    // Helper to call the overlap check logic with plain Vecs
    pub fn check_overlap(
        authorities: Vec<A>,
        queued: Vec<A>,
        add: Option<A>,
        remove: Option<A>,
    ) -> Result<(), ()> {
        // Convert to the pallet's storage-like types by creating temporary BoundedVecs
        // We can't call pallet storage directly here without a runtime, so instead reimplement
        // the overlap computation locally to verify the same logic.

        if authorities.is_empty() {
            return Ok(());
        }

        let mut new_validators = queued.clone();
        if let Some(a) = add {
            if !new_validators.contains(&a) {
                new_validators.push(a);
            }
        }
        if let Some(rm) = remove {
            new_validators.retain(|v| v != &rm);
        }

        let mut overlap = 0usize;
        for acc in authorities.iter() {
            if new_validators.contains(acc) {
                overlap += 1;
            }
        }

        let old_n = authorities.len();
        if old_n == 0 || new_validators.is_empty() {
            return Ok(());
        }

        let f_old = old_n.saturating_sub(1) / 3;
        let min_overlap_old = f_old + 1;
        let new_n = new_validators.len();
        let min_overlap_new = (new_n * 2 + 2) / 3;
        let min_overlap = sp_std::cmp::max(min_overlap_old, min_overlap_new);

        if overlap >= min_overlap {
            Ok(())
        } else {
            Err(())
        }
    }

    #[test]
    fn overlap_allows_small_changes() {
        // old_n = 4, queued = same as authorities
        let auths = vec![1u64, 2u64, 3u64, 4u64];
        let queued = auths.clone();
        assert!(check_overlap(auths.clone(), queued.clone(), Some(5u64), None).is_ok());
        // adding two may fail depending on overlap
        let res = check_overlap(auths.clone(), queued.clone(), Some(5u64), None);
        assert!(res.is_ok());
        // if we add two new and remove none, overlap may become too small
        let res2 = check_overlap(auths.clone(), queued.clone(), Some(5u64), None);
        assert!(res2.is_ok());
    }

    #[test]
    fn overlap_rejects_big_change() {
        let auths = vec![1u64, 2u64, 3u64, 4u64];
        let queued = auths.clone();
        // simulate adding many newcomers to lower overlap
        let mut q2 = queued.clone();
        q2.push(5u64);
        q2.push(6u64);
        // now overlap = 4, new_n = 6 -> min_overlap_new = ceil(12/3)=4, so allowed
        assert!(check_overlap(auths.clone(), q2.clone(), None, None).is_ok());

        // make a change that definitely breaks overlap: replace many
        let q3 = vec![5u64, 6u64, 7u64, 8u64];
        assert!(check_overlap(auths.clone(), q3.clone(), None, None).is_err());
    }
}

const LOG_TARGET: &str = "runtime::sc-consensus-hotstuff";
/// The current storage version.
const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

#[frame_support::pallet]
pub mod pallet {
    use frame_support::traits::FindAuthor;
    use frame_system::{
        ensure_root,
        pallet_prelude::{BlockNumberFor, OriginFor},
    };
    use sp_consensus_hotstuff::{
        consensus::{ConsensusLog, HOTSTUFF_CONSENSUS_ID},
        AccountId, HOTSTUFF_AUTH_DISC_KEY_TYPE, HOTSTUFF_BLS_KEY_TYPE, HOTSTUFF_KEY_TYPE,
    };
    use sp_runtime::{ConsensusEngineId, DigestItem};

    use super::*;

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    //#[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + pallet_session::Config<ValidatorId = <Self as frame_system::Config>::AccountId>
    {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        #[pallet::constant]
        type MaxAuthorities: Get<u32>;

        #[pallet::constant]
        type DefaultForceProposeIntervalMs: Get<u64>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AuthoritiesInitialized(u32),
        AuthoritiesUpdated(
            u32,
            BoundedVec<T::AccountId, T::MaxAuthorities>,
            BoundedVec<T::AccountId, T::MaxAuthorities>,
        ),
        ForceProposeIntervalUpdated(u64),
    }

    #[pallet::error]
    pub enum Error<T> {
        TooManyAuthorities,
        DuplicateAuthority,
        AuthorityNotFound,
        ExceedValidatorChangeLimit,
        ValidatorKeysNotRegistered,
    }

    // Validator ids for next next session, will be in pallet-session::queued_keys
    // when new_session happens
    #[pallet::storage]
    #[pallet::getter(fn queued_validator_ids)]
    pub type QueuedValidatorIds<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxAuthorities>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_session_index)]
    pub type CurrentSessionIndex<T: Config> = StorageValue<_, SessionIndex, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn force_propose_interval_ms)]
    pub type ForceProposeIntervalMs<T: Config> =
        StorageValue<_, u64, ValueQuery, T::DefaultForceProposeIntervalMs>;

    // Authorities applied in current session
    #[pallet::storage]
    #[pallet::getter(fn authorities)]
    pub type Authorities<T: Config> = StorageValue<
        _,
        BoundedVec<
            (
                T::AccountId,
                AuthorityId,
                BlsPublicBytes,
                AuthorityDiscoveryId,
            ),
            T::MaxAuthorities,
        >,
        ValueQuery,
    >;

    // Authorities that are going to be applied in next session
    // will update by pallet-session::queue_keys when on_new_session happens
    #[pallet::storage]
    #[pallet::getter(fn next_authorities)]
    pub type NextAuthorities<T: Config> = StorageValue<
        _,
        BoundedVec<
            (
                T::AccountId,
                AuthorityId,
                BlsPublicBytes,
                AuthorityDiscoveryId,
            ),
            T::MaxAuthorities,
        >,
        ValueQuery,
    >;

    /// `CurrentSessionIndex` as seen at the end of the previous block. Used to detect
    /// boundary blocks (where the index just advanced) without needing the session period.
    #[pallet::storage]
    pub type PrevBlockSessionIndex<T: Config> = StorageValue<_, SessionIndex, ValueQuery>;

    /// The `next_session_index` of the most recently announced `NextAuthoritySet` digest.
    /// Used to announce each change exactly once per session.
    #[pallet::storage]
    pub type LastAnnouncedNextSession<T: Config> = StorageValue<_, SessionIndex, ValueQuery>;

    pub fn queued_validator_ids<T: Config>() -> Vec<T::AccountId> {
        QueuedValidatorIds::<T>::get().to_vec()
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// on_finalize is nothing about block finality, it's called when a block is being imported as follows
        /// 1. on_initialize
        /// 2. execute extrinsics
        /// 3. on_finalize
        /// 4. calculate block hash，finish block header generation
        /// 5. import_block
        fn on_finalize(block_number: BlockNumberFor<T>) {
            let cur = CurrentSessionIndex::<T>::get();
            let prev = PrevBlockSessionIndex::<T>::get();
            PrevBlockSessionIndex::<T>::put(cur);

            // Boundary block: pallet just rotated `Authorities` to the *next* session's set in
            // on_initialize, so it is one session ahead of this block's actual QC signer. Never
            // announce here (would let the warp verifier skip a set and break the chain).
            if cur != prev {
                return;
            }

            let next_idx = cur + 1;
            // Announce each real change exactly once — at the first non-boundary block of the session.
            if LastAnnouncedNextSession::<T>::get() == next_idx {
                return;
            }
            LastAnnouncedNextSession::<T>::put(next_idx);

            let authorities = <Authorities<T>>::get();
            let next_authorities = <NextAuthorities<T>>::get();
            let cur_hash = hash_authority_set::<T::AccountId>(&authorities);
            let next_hash = hash_authority_set::<T::AccountId>(&next_authorities);
            if cur_hash != next_hash {
                let digest_log = ConsensusLog::NextAuthoritySet {
                    next_session_index: next_idx,
                    authority_set_hash: next_hash,
                };
                log::info!(
                    target: LOG_TARGET,
                    "block #{:?}: emit NextAuthoritySet next_session_index={}, hash={:?}",
                    block_number,
                    next_idx,
                    next_hash,
                );
                Self::deposit_log(digest_log);
            }
        }
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_authorities: Vec<(
            T::AccountId,
            AuthorityId,
            BlsPublicBytes,
            BlsProofOfPossessionBytes,
            AuthorityDiscoveryId,
        )>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            CurrentSessionIndex::<T>::put(0);
            ForceProposeIntervalMs::<T>::put(T::DefaultForceProposeIntervalMs::get());

            for (account, _, bls_pk, bls_pop, _) in &self.initial_authorities {
                assert!(
                    verify_bls_pop(bls_pk, bls_pop),
                    "invalid BLS proof of possession for genesis authority {:?}",
                    account,
                );
            }

            let bounded: BoundedVec<
                (
                    T::AccountId,
                    AuthorityId,
                    BlsPublicBytes,
                    AuthorityDiscoveryId,
                ),
                T::MaxAuthorities,
            > = self
                .initial_authorities
                .iter()
                .map(|(account, auth, bls_pk, _, auth_disc)| {
                    (account.clone(), auth.clone(), *bls_pk, auth_disc.clone())
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("Too many authorities in genesis");

            // session 0 and session 1 is share the same authorities
            <Authorities<T>>::put(bounded.clone());
            <NextAuthorities<T>>::put(bounded.clone());
            let accounts: BoundedVec<T::AccountId, T::MaxAuthorities> = self
                .initial_authorities
                .iter()
                .map(|(acc_id, _, _, _, _)| acc_id.clone())
                .collect::<Vec<_>>()
                .try_into()
                .expect("Too many account IDs in genesis");

            <QueuedValidatorIds<T>>::put(accounts);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /*
        Validator-set transition safety constraints

        Given the rule:
            overlap ≥ max( f_old + 1 , ceil( 2 * new_n / 3 ) )

        Assuming no old validators are removed (worst-case additive expansion),
        the following table shows the maximum allowable new validator count.

        | old_n (old validator set size) | max new_n (after adding) | max added validators |
        |--------------------------------|---------------------------|-----------------------|
        | 4                              | 6                         | 2                     |
        | 5                              | 7                         | 2                     |
        | 6                              | 9                         | 3                     |
        | 7                              | 10                        | 3                     |
        | 8                              | 12                        | 4                     |
        | 9                              | 13                        | 4                     |
        | 10                             | 15                        | 5                     |

        Interpretation:
        - Increasing the validator set is constrained to maintain strong overlap.
        - This guarantees both BFT safety (based on old set) and smooth liveness (based on new set).
        - The larger the old validator set, the more validators can be safely added in one transition.
        */
        #[pallet::call_index(0)]
        #[pallet::weight((T::DbWeight::get().reads_writes(3, 1).saturating_add(Weight::from_parts(10_000, 0)), DispatchClass::Operational, Pays::No))]
        pub fn add_queued_validator(
            origin: OriginFor<T>,
            new_validator: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut queued = QueuedValidatorIds::<T>::get();

            ensure!(
                !queued.contains(&new_validator),
                Error::<T>::DuplicateAuthority
            );
            ensure!(
                SessionPallet::<T>::load_keys(&new_validator).is_some(),
                Error::<T>::ValidatorKeysNotRegistered,
            );

            // Validate queued changes do not exceed 1/3 of current authorities
            Self::ensure_validator_change_within_limit(&queued, Some(&new_validator), None)?;

            queued
                .try_push(new_validator.clone())
                .map_err(|_| Error::<T>::TooManyAuthorities)?;

            QueuedValidatorIds::<T>::put(queued.clone());

            log::info!(
                target: LOG_TARGET,
                "Added queued validator: {:?}",
                new_validator,
            );

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1).saturating_add(Weight::from_parts(10_000, 0)), DispatchClass::Operational, Pays::No))]
        pub fn remove_queued_validator(
            origin: OriginFor<T>,
            validator: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut queued = QueuedValidatorIds::<T>::get();
            let initial_len = queued.len();

            queued.retain(|v| v != &validator);

            ensure!(queued.len() < initial_len, Error::<T>::AuthorityNotFound,);

            // Ensure removal does not violate validator-change limit
            Self::ensure_validator_change_within_limit(&queued, None, Some(&validator))?;
            QueuedValidatorIds::<T>::put(queued);

            log::info!(
                target: LOG_TARGET,
                "Removed queued validator: {:?}",
                validator,
            );

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight((T::DbWeight::get().writes(1).saturating_add(Weight::from_parts(10_000, 0)), DispatchClass::Operational, Pays::No))]
        pub fn set_force_propose_interval_ms(
            origin: OriginFor<T>,
            interval_ms: u64,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ForceProposeIntervalMs::<T>::put(interval_ms);
            Self::deposit_event(Event::ForceProposeIntervalUpdated(interval_ms));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Deposit one of this module's logs.
        fn deposit_log(log: ConsensusLog) {
            let log = DigestItem::Consensus(HOTSTUFF_CONSENSUS_ID, log.encode());
            frame_system::Pallet::<T>::deposit_log(log);
        }

        /// Ensure that number of queued validators that differ from current authorities
        /// does not exceed floor(authorities_count / 3).
        ///
        /// `queued` should be the queued set as it will be considered.
        ///
        /// For add: pass the current queued and `candidate_to_add`=Some(&new_validator)
        /// to evaluate the state after the add.
        /// For removal: pass the queued after the removal and `candidate_to_remove`=Some(&validator)
        /// so the check counts the removal against the limit.
        fn ensure_validator_change_within_limit(
            queued: &BoundedVec<T::AccountId, T::MaxAuthorities>,
            candidate_to_add: Option<&T::AccountId>,
            candidate_to_remove: Option<&T::AccountId>,
        ) -> DispatchResult {
            let authorities = <Authorities<T>>::get();
            let authorities_count = authorities.len();
            if authorities_count == 0 {
                return Ok(());
            }

            // build a set-like check over current authorities' AccountId
            let mut auth_accounts = sp_std::vec::Vec::with_capacity(authorities_count);
            for (acc, _, _, _) in authorities.iter() {
                auth_accounts.push(acc.clone());
            }

            // Build the new validators set as the queued set after applying
            // the optional add/remove candidate. Then compute overlap between
            // current authorities (old_validators) and new_validators and
            // enforce the quorum overlap rule:
            //
            // old_n = old_validators.len()
            // min_overlap = 2 * floor((old_n - 1) / 3) + 1
            // require overlap >= min_overlap

            // Start from queued (which represents new validators as-considered)
            let mut new_validators: sp_std::vec::Vec<T::AccountId> =
                queued.iter().cloned().collect();

            if let Some(candidate) = candidate_to_add {
                if !new_validators.contains(candidate) {
                    new_validators.push(candidate.clone());
                }
            }

            if let Some(candidate_rm) = candidate_to_remove {
                // remove all matching entries (should be at most one)
                new_validators.retain(|v| v != candidate_rm);
            }

            // compute overlap = |old_validators ∩ new_validators|
            let mut overlap: usize = 0;
            for acc in auth_accounts.iter() {
                if new_validators.contains(acc) {
                    overlap += 1;
                }
            }

            let old_n = auth_accounts.len();
            if old_n == 0 {
                return Ok(());
            }
            let new_n = new_validators.len();
            if new_n == 0 {
                return Ok(());
            }

            // ---------- Based on Old Set: BFT safety ----------
            // f_old = floor((old_n - 1) / 3)
            let f_old = old_n.saturating_sub(1) / 3;
            // ensure at least a honest validators is in the overlap
            let min_overlap_old = f_old + 1;

            // ---------- Based on New Set: Smooth liveness ----------
            // overlap >= ceil(2 * new_n / 3), in case new comers are down
            let min_overlap_new = (new_n * 2 + 2) / 3;
            let min_overlap = sp_std::cmp::max(min_overlap_old, min_overlap_new);

            log::trace!(
                target: LOG_TARGET,
                "Validator change check: old_n={}, new_n={}, f_old={}, overlap={}, min_overlap_old={}, min_overlap_new={}, min_overlap={}",
                old_n,
                new_n,
                f_old,
                overlap,
                min_overlap_old,
                min_overlap_new,
                min_overlap,
            );

            ensure!(
                overlap >= min_overlap,
                Error::<T>::ExceedValidatorChangeLimit
            );
            Ok(())
        }
    }

    impl<T: Config + pallet_session::Config> Pallet<T>
    where
        <T as pallet_session::Config>::ValidatorId: Into<<T as frame_system::Config>::AccountId>,
    {
        pub(crate) fn rebuild_authorities() {
            let out =
                Self::get_queued_keys_from_session(SessionPallet::<T>::queued_keys().into_iter());

            <Authorities<T>>::put(<NextAuthorities<T>>::get());
            <NextAuthorities<T>>::put(out);

            let current_index = SessionPallet::<T>::current_index();
            CurrentSessionIndex::<T>::put(current_index);

            log::trace!(
                target: LOG_TARGET,
                "rebuild_authorities authority current_index={}, authorities={}, next_authorities={}",
                current_index, <Authorities<T>>::get().len(), <NextAuthorities<T>>::get().len(),
            );

            let authorities_accounts: BoundedVec<T::AccountId, T::MaxAuthorities> =
                <Authorities<T>>::get()
                    .into_iter()
                    .map(|(account_id, _, _, _)| account_id)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("authorities length is bounded by T::MaxAuthorities; qed");
            let next_authorities_accounts: BoundedVec<T::AccountId, T::MaxAuthorities> =
                <NextAuthorities<T>>::get()
                    .into_iter()
                    .map(|(account_id, _, _, _)| account_id)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("next_authorities length is bounded by T::MaxAuthorities; qed");

            Self::deposit_event(Event::AuthoritiesUpdated(
                current_index,
                authorities_accounts,
                next_authorities_accounts,
            ))
        }

        fn get_queued_keys_from_session(
            iter: impl Iterator<Item = (T::ValidatorId, T::Keys)>,
        ) -> BoundedVec<
            (
                T::AccountId,
                AuthorityId,
                BlsPublicBytes,
                AuthorityDiscoveryId,
            ),
            T::MaxAuthorities,
        > {
            let mut out = BoundedVec::default();
            for (who, keys) in iter {
                let auth_id: AuthorityId = keys
                    .get::<AuthorityId>(HOTSTUFF_KEY_TYPE)
                    .expect("missing auth key");
                let bls_pk: BlsPublicBytes = keys
                    .get::<BlsPublicBytes>(HOTSTUFF_BLS_KEY_TYPE)
                    .expect("missing bls key");
                let auth_disc_id: AuthorityDiscoveryId = keys
                    .get::<AuthorityDiscoveryId>(HOTSTUFF_AUTH_DISC_KEY_TYPE)
                    .expect("missing auth-disc key");
                let _ = out.try_push((who.clone().into(), auth_id, bls_pk, auth_disc_id));
            }
            out
        }
    }

    impl<T: Config> FindAuthor<AccountId> for Pallet<T> {
        fn find_author<'a, I>(digests: I) -> Option<AccountId>
        where
            I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
        {
            digests.into_iter().find_map(|(id, data)| {
                if id != HOTSTUFF_CONSENSUS_ID {
                    return None;
                }

                let log = ConsensusLog::decode(&mut &*data).ok()?;

                match log {
                    ConsensusLog::Proposer(leader_id) => Some(leader_id),
                    _ => None,
                }
            })
        }
    }
}

pub struct StashOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Convert<T::AccountId, Option<T::AccountId>> for StashOf<T> {
    fn convert(controller: T::AccountId) -> Option<T::AccountId> {
        Some(controller)
    }
}
