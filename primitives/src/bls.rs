use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    Bls12, G1Affine, G2Affine, G2Projective, Gt,
};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use pairing_lib::MultiMillerLoop;
use scale_info::TypeInfo;
use sp_runtime::{KeyTypeId, RuntimeAppPublic};

extern crate alloc;
use serde::{Deserializer, Serializer};

use crate::HOTSTUFF_BLS_KEY_TYPE;

pub type BlsPkType = [u8; 48];
pub type BlsSigType = [u8; 96];

/* bls structures, no std required, used by runtime */
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct BlsPublicBytes(#[serde(with = "serde_bls_pk_hex")] pub BlsPkType);

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct BlsSignatureBytes(#[serde(with = "serde_bls_sig_hex")] pub BlsSigType);

pub type BlsProofOfPossessionBytes = BlsSignatureBytes;

/// Domain separation tag for the IETF BLS proof-of-possession ciphersuite used by Hotstuff.
///
/// Keep this as the single source of truth for both off-chain PoP generation and runtime
/// verification. Hotstuff uses the minimal-public-key-size variant: public keys are in G1 and
/// signatures/PoPs are in G2.
pub const BLS_POP_CIPHERSUITE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Versioned payload accepted by `pallet_session::set_keys` as its opaque proof bytes.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, Debug)]
pub enum SessionKeysProof {
    #[codec(index = 0)]
    V1 { bls_pop: BlsProofOfPossessionBytes },
}

impl DecodeWithMemTracking for SessionKeysProof {}

/// Verify that `bls_pop` proves knowledge of the secret key for `public_key`.
///
/// This verifier intentionally lives in the no_std primitives layer so it can execute inside the
/// runtime Wasm during session-key admission. The native `sc-consensus-hotstuff-bls` verifier normally uses
/// the faster `blst` backend, but that C/assembly-backed implementation is not available to the
/// deterministic Wasm runtime without adding a consensus-critical host function.
///
/// Compressed point decoding performs curve and subgroup checks. Identity points are rejected
/// explicitly, even though they are valid compressed curve encodings.
pub fn verify_bls_pop(public_key: &BlsPublicBytes, bls_pop: &BlsProofOfPossessionBytes) -> bool {
    let Ok(public_key_bytes) = <[u8; 48]>::try_from(public_key.as_slice()) else {
        return false;
    };
    let Some(public_key) = Option::<G1Affine>::from(G1Affine::from_compressed(&public_key_bytes))
    else {
        return false;
    };
    if bool::from(public_key.is_identity()) {
        return false;
    }

    let Ok(pop_bytes) = <[u8; 96]>::try_from(bls_pop.as_slice()) else {
        return false;
    };
    let Some(pop) = Option::<G2Affine>::from(G2Affine::from_compressed(&pop_bytes)) else {
        return false;
    };
    if bool::from(pop.is_identity()) {
        return false;
    }

    let message_hash = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        &public_key_bytes,
        BLS_POP_CIPHERSUITE,
    );
    let message_hash = G2Affine::from(message_hash);

    // e(pk, H_POP(pk)) == e(G1, pop)
    let lhs = Bls12::multi_miller_loop(&[(&public_key, &message_hash.into())]);
    let neg_generator = -G1Affine::generator();
    let rhs = Bls12::multi_miller_loop(&[(&neg_generator, &pop.into())]);

    (lhs + rhs).final_exponentiation() == Gt::identity()
}

impl BlsPublicBytes {
    #[inline]
    pub const fn new(bytes: BlsPkType) -> Self {
        Self(bytes)
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl BlsSignatureBytes {
    #[inline]
    pub const fn new(bytes: BlsSigType) -> Self {
        Self(bytes)
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for BlsPublicBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlsPublicBytes(0x{})", hex::encode(self.0))
    }
}

impl core::fmt::Display for BlsPublicBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl core::fmt::Debug for BlsSignatureBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlsSignatureBytes(96B)")
    }
}

impl core::fmt::Display for BlsSignatureBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<BlsPkType> for BlsPublicBytes {
    fn from(b: BlsPkType) -> Self {
        Self(b)
    }
}

impl From<BlsSigType> for BlsSignatureBytes {
    fn from(b: BlsSigType) -> Self {
        Self(b)
    }
}

impl AsRef<[u8]> for BlsPublicBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for BlsSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DecodeWithMemTracking for BlsPublicBytes {}
impl DecodeWithMemTracking for BlsSignatureBytes {}

impl Default for BlsPublicBytes {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl Default for BlsSignatureBytes {
    fn default() -> Self {
        Self([0u8; 96])
    }
}

mod serde_bls_pk_hex {
    use super::*;
    use core::fmt;
    use serde::de::Error;

    const LEN: usize = 48;

    pub fn serialize<S>(bytes: &BlsPkType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = hex::encode(bytes);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlsPkType, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BlsPkType;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "48-byte hex string, or array/bytes of length 48")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let v = hex::decode(s).map_err(E::custom)?;
                if v.len() != LEN {
                    return Err(E::custom("expected 48 bytes hex"));
                }
                let mut arr = [0u8; LEN];
                arr.copy_from_slice(&v);
                Ok(arr)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; LEN];
                for item in arr.iter_mut().take(LEN) {
                    *item = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| A::Error::custom("expected 48 elements"))?;
                }
                Ok(arr)
            }

            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                if b.len() != LEN {
                    return Err(E::custom("expected 48 bytes"));
                }
                let mut arr = [0u8; LEN];
                arr.copy_from_slice(b);
                Ok(arr)
            }
        }

        deserializer.deserialize_any(V)
    }
}

mod serde_bls_sig_hex {
    use super::*;
    use core::fmt;
    use serde::de::Error;

    const LEN: usize = 96;

    pub fn serialize<S>(bytes: &BlsSigType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = hex::encode(bytes);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlsSigType, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BlsSigType;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "96-byte hex string, or array/bytes of length 96")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let v = hex::decode(s).map_err(E::custom)?;
                if v.len() != LEN {
                    return Err(E::custom("expected 96 bytes hex"));
                }
                let mut arr = [0u8; LEN];
                arr.copy_from_slice(&v);
                Ok(arr)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; LEN];
                for item in arr.iter_mut().take(LEN) {
                    *item = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| A::Error::custom("expected 96 elements"))?;
                }
                Ok(arr)
            }

            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                if b.len() != LEN {
                    return Err(E::custom("expected 96 bytes"));
                }
                let mut arr = [0u8; LEN];
                arr.copy_from_slice(b);
                Ok(arr)
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl RuntimeAppPublic for BlsPublicBytes {
    const ID: KeyTypeId = HOTSTUFF_BLS_KEY_TYPE;

    type Signature = BlsSignatureBytes;

    type ProofOfPossession = BlsSignatureBytes;

    fn all() -> sp_std::vec::Vec<Self> {
        sp_std::vec::Vec::new()
    }

    fn generate_pair(_seed: Option<sp_std::vec::Vec<u8>>) -> Self {
        unreachable!("BlsPublicBytes::generate_pair is not supported for this key type")
    }

    fn sign<M: AsRef<[u8]>>(&self, _msg: &M) -> Option<Self::Signature> {
        None
    }

    fn verify<M: AsRef<[u8]>>(&self, _msg: &M, _signature: &Self::Signature) -> bool {
        false
    }

    fn generate_proof_of_possession(&mut self, _owner: &[u8]) -> Option<Self::ProofOfPossession> {
        None
    }

    fn verify_proof_of_possession(&self, _owner: &[u8], pop: &Self::ProofOfPossession) -> bool {
        verify_bls_pop(self, pop)
    }

    fn to_raw_vec(&self) -> sp_std::vec::Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_identity_and_malformed_points() {
        let identity_pk = BlsPublicBytes::new(G1Affine::identity().to_compressed());
        let identity_pop = BlsSignatureBytes::new(G2Affine::identity().to_compressed());
        assert!(!verify_bls_pop(&identity_pk, &identity_pop));

        assert!(!verify_bls_pop(
            &BlsPublicBytes::new([0xff; 48]),
            &BlsSignatureBytes::new([0xff; 96]),
        ));
    }

    #[test]
    fn rejects_a_compressed_curve_point_outside_the_g1_subgroup() {
        // Compressed x=0 decodes to a point on the BLS12-381 curve, but not to the prime-order G1
        // subgroup. The unchecked decoder proves this is a subgroup test rather than malformed
        // compression data.
        let mut non_subgroup_pk = [0u8; 48];
        non_subgroup_pk[0] = 0x80;
        let unchecked =
            Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&non_subgroup_pk))
                .expect("x=0 is a compressed curve point");
        assert!(!bool::from(unchecked.is_torsion_free()));

        let well_formed_pop = BlsSignatureBytes::new(G2Affine::generator().to_compressed());
        assert!(!verify_bls_pop(
            &BlsPublicBytes::new(non_subgroup_pk),
            &well_formed_pop,
        ));
    }
}
