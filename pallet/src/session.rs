use log;
use sp_std::marker::PhantomData;

use crate::Pallet;
use crate::{queued_validator_ids, Config, LOG_TARGET};
use frame_support::{sp_runtime::BoundToRuntimeAppPublic, traits::OneSessionHandler};
use sp_consensus_hotstuff::{AuthorityId, BlsPublicBytes, SessionIndex};
use sp_std::vec::Vec;

// TODO use pallet-staking SessionManager
pub struct HotstuffSessionManager<T>(PhantomData<T>);
impl<T> pallet_session::SessionManager<T::AccountId> for HotstuffSessionManager<T>
where
    T: Config + pallet_session::Config,
{
    fn new_session(_new_index: SessionIndex) -> Option<Vec<T::AccountId>> {
        let ids = queued_validator_ids::<T>();
        // for debugging
        // if new_index & 1 == 0 {
        //     Some(ids[..ids.len() - 1].to_vec())
        // } else {
        Some(ids)
        // }
    }

    fn new_session_genesis(_new_index: SessionIndex) -> Option<Vec<T::AccountId>> {
        // authorities of gensis session is set by chain_spec directly
        None
    }

    fn end_session(_end_index: SessionIndex) {}

    fn start_session(_start_index: SessionIndex) {}
}

pub struct AuthoritySessionHandler<T>(PhantomData<T>);

impl<T: Config + pallet_session::Config> BoundToRuntimeAppPublic for AuthoritySessionHandler<T> {
    type Public = AuthorityId;
}

impl<T: Config + pallet_session::Config> OneSessionHandler<T::AccountId>
    for AuthoritySessionHandler<T>
where
    <T as pallet_session::Config>::ValidatorId: Into<<T as frame_system::Config>::AccountId>,
{
    type Key = AuthorityId;

    fn on_genesis_session<'a, I>(_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, AuthorityId)>,
        T::AccountId: 'a,
    {
    }

    fn on_new_session<'a, I>(changed: bool, _: I, queued_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, AuthorityId)>,
        T::AccountId: 'a,
    {
        log::trace!(
            target: LOG_TARGET,
            "on_new_session authority changed={}, validators: {:?}",
            changed, queued_validators.collect::<Vec<_>>(),
        );

        Pallet::<T>::rebuild_authorities();
    }

    fn on_disabled(_validator_index: u32) {}
}

pub struct BlsSessionHandler<T>(PhantomData<T>);

impl<T: Config> BoundToRuntimeAppPublic for BlsSessionHandler<T> {
    type Public = BlsPublicBytes;
}

impl<T: Config> OneSessionHandler<T::AccountId> for BlsSessionHandler<T> {
    type Key = BlsPublicBytes;

    fn on_genesis_session<'a, I>(validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, BlsPublicBytes)>,
        T::AccountId: 'a,
    {
        // `pallet_session` inserts genesis keys before invoking this handler, while the Hotstuff
        // genesis config has already populated `Authorities`. Comparing them here makes the
        // invariant hold even for externally supplied non-raw chain specs instead of relying only
        // on the bootstrapper constructing both fields from the same input vector.
        let session_bls_keys = validators
            .map(|(account, bls_pk)| (account.clone(), bls_pk))
            .collect::<Vec<_>>();
        let authorities = Pallet::<T>::authorities();
        let registered_key_count = pallet_session::NextKeys::<T>::iter().count();

        assert_eq!(
            session_bls_keys.len(),
            authorities.len(),
            "genesis session keys and Hotstuff authorities must contain the same validators",
        );
        assert_eq!(
            registered_key_count,
            authorities.len(),
            "genesis non-authority session keys bypass PoP admission; register them after genesis",
        );

        for (account, _, expected_bls_pk, _) in authorities.iter() {
            let (_, actual_bls_pk) = session_bls_keys
                .iter()
                .find(|(session_account, _)| session_account == account)
                .unwrap_or_else(|| {
                    panic!(
                        "missing genesis session BLS key for Hotstuff authority {:?}",
                        account
                    )
                });
            assert_eq!(
                actual_bls_pk, expected_bls_pk,
                "genesis session BLS key does not match Hotstuff authority {:?}",
                account,
            );
        }
    }

    fn on_new_session<'a, I>(_changed: bool, _: I, _queued_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, BlsPublicBytes)>,
        T::AccountId: 'a,
    {
    }

    fn on_disabled(_validator_index: u32) {}
}
