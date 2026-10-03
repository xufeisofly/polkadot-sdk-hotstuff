use super::*;
use codec::{Decode, DecodeAll, DecodeWithMemTracking};
use scale_info::TypeInfo;
use sp_runtime::{traits::OpaqueKeys, RuntimeAppPublic};
use sp_std::vec;
#[derive(
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(crate = "serde")]
pub struct SessionKeys {
    pub auth: AuthorityId,
    pub bls_pk: BlsPublicBytes,
    pub auth_disc: AuthorityDiscoveryId,
}

impl SessionKeys {
    pub fn into_raw_public_keys(self) -> Vec<(Vec<u8>, KeyTypeId)> {
        vec![
            (self.auth.to_raw_vec(), AuthorityId::ID),
            (self.bls_pk.to_raw_vec(), BlsPublicBytes::ID),
            (self.auth_disc.to_raw_vec(), AuthorityDiscoveryId::ID),
        ]
    }

    pub fn decode_into_raw_public_keys(encoded: &[u8]) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
        Self::decode(&mut &encoded[..])
            .ok()
            .map(Self::into_raw_public_keys)
    }
}

impl OpaqueKeys for SessionKeys {
    type KeyTypeIdProviders = (AuthorityId, BlsPublicBytes, AuthorityDiscoveryId);

    fn key_ids() -> &'static [KeyTypeId] {
        &[
            AuthorityId::ID,
            BlsPublicBytes::ID,
            AuthorityDiscoveryId::ID,
        ]
    }

    fn get_raw(&self, id: KeyTypeId) -> &[u8] {
        match id {
            id if id == AuthorityId::ID => self.auth.as_ref(),
            id if id == BlsPublicBytes::ID => self.bls_pk.as_ref(),
            id if id == AuthorityDiscoveryId::ID => self.auth_disc.as_ref(),
            _ => &[],
        }
    }

    fn ownership_proof_is_valid(&self, _owner: &[u8], proof: &[u8]) -> bool {
        let valid = match SessionKeysProof::decode_all(&mut &proof[..]) {
            Ok(SessionKeysProof::V1 { bls_pop }) => verify_bls_pop(&self.bls_pk, &bls_pop),
            Err(_) => false,
        };

        valid
    }
}
