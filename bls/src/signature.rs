use std::{collections::HashSet, io};

#[cfg(feature = "multicore")]
use rayon::prelude::*;

#[cfg(feature = "pairing")]
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    Bls12, G1Affine, G2Affine, G2Projective, Gt, MillerLoopResult,
};
use pairing_lib::MultiMillerLoop;

#[cfg(feature = "blst")]
use blstrs::{Bls12, G1Affine, G2Affine, G2Projective, Gt, MillerLoopResult};
#[cfg(feature = "blst")]
use group::{prime::PrimeCurveAffine, Group};
#[cfg(feature = "blst")]
use pairing_lib::MillerLoopResult as _;

use crate::error::Error;
use crate::key::*;
use codec::{Decode, Encode};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
use sp_consensus_hotstuff::BLS_POP_CIPHERSUITE;
const G2_COMPRESSED_SIZE: usize = 96;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct Signature(G2Affine);

pub type ProofOfPossession = Signature;

impl From<G2Projective> for Signature {
    fn from(val: G2Projective) -> Self {
        Signature(val.into())
    }
}
impl From<Signature> for G2Projective {
    fn from(val: Signature) -> Self {
        val.0.into()
    }
}

impl From<G2Affine> for Signature {
    fn from(val: G2Affine) -> Self {
        Signature(val)
    }
}

impl From<Signature> for G2Affine {
    fn from(val: Signature) -> Self {
        val.0
    }
}

impl Serialize for Signature {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        dest.write_all(&self.0.to_compressed())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let g2 = g2_from_slice(raw)?;
        Ok(g2.into())
    }
}

fn g2_from_slice(raw: &[u8]) -> Result<G2Affine, Error> {
    if raw.len() != G2_COMPRESSED_SIZE {
        return Err(Error::SizeMismatch);
    }

    let mut res = [0u8; G2_COMPRESSED_SIZE];
    res.copy_from_slice(raw);

    Option::from(G2Affine::from_compressed(&res)).ok_or(Error::GroupDecode)
}

/// Hash the given message, as used in the signature.
#[cfg(feature = "pairing")]
pub fn hash(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, CSUITE)
}

#[cfg(feature = "blst")]
pub fn hash(msg: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, CSUITE, &[])
}

/// could use public_key.verify, which is actually verify_aggregated, verify_one's logic is simpler.
#[cfg(feature = "pairing")]
pub fn verify_one(signature: &Signature, message: &[u8], public_key: &PublicKey) -> bool {
    if public_key.0.is_identity().into() {
        return false;
    }

    let message_hash = hash(message);
    let message_hash_affine = G2Affine::from(message_hash);
    let pk_affine = public_key.as_affine();

    let lhs = Bls12::multi_miller_loop(&[(&pk_affine, &message_hash_affine.into())]);
    let g1_neg = -G1Affine::generator();
    let rhs = Bls12::multi_miller_loop(&[(&g1_neg, &signature.0.into())]);

    let ml = lhs + rhs;
    ml.final_exponentiation() == Gt::identity()
}

#[cfg(feature = "blst")]
pub fn verify_one(signature: &Signature, message: &[u8], public_key: &PublicKey) -> bool {
    if public_key.0.is_identity().into() {
        return false;
    }

    // Use BLST's optimized single signature verification
    let mut pairing = blstrs::PairingG1G2::new(true, CSUITE);

    if pairing
        .aggregate(&public_key.0.into(), None, message, &[])
        .is_err()
    {
        return false;
    }
    pairing.commit();

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &signature.0);

    pairing.finalverify(Some(&gtsig))
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
#[cfg(feature = "multicore")]
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, Error> {
    if signatures.is_empty() {
        return Err(Error::ZeroSizedInput);
    }

    let res = signatures
        .into_par_iter()
        .fold(G2Projective::identity, |mut acc, signature| {
            acc += &signature.0;
            acc
        })
        .reduce(G2Projective::identity, |acc, val| acc + val);

    Ok(Signature(res.into()))
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
#[cfg(not(feature = "multicore"))]
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, Error> {
    if signatures.is_empty() {
        return Err(Error::ZeroSizedInput);
    }

    let res = signatures
        .iter()
        .fold(G2Projective::identity(), |acc, signature| acc + signature.0);

    Ok(Signature(res.into()))
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify(signature: &Signature, hashes: &[G2Projective], public_keys: &[PublicKey]) -> bool {
    if hashes.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_hashes = hashes.len();

    if n_hashes != public_keys.len() {
        return false;
    }

    // zero keys should always fail.
    if public_keys.iter().any(|pk| pk.0.is_identity().into()) {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    if hashes
        .iter()
        // This is the best way to get something we can actually hash.
        .map(|h| G2Affine::from(h).to_compressed())
        .collect::<HashSet<_>>()
        .len()
        != hashes.len()
    {
        return false;
    }

    #[cfg(feature = "multicore")]
    let mut ml = public_keys
        .par_iter()
        .zip(hashes.par_iter())
        .map(|(pk, h)| {
            let pk = pk.as_affine();
            let h = G2Affine::from(h).into();
            Bls12::multi_miller_loop(&[(&pk, &h)])
        })
        .reduce(MillerLoopResult::default, |acc, cur| acc + cur);

    #[cfg(not(feature = "multicore"))]
    let mut ml = public_keys
        .iter()
        .zip(hashes.iter())
        .map(|(pk, h)| {
            let pk = pk.as_affine();
            let h = G2Affine::from(h).into();
            Bls12::multi_miller_loop(&[(&pk, &h)])
        })
        .fold(MillerLoopResult::default(), |acc, cur| acc + cur);

    let g1_neg = -G1Affine::generator();

    ml += Bls12::multi_miller_loop(&[(&g1_neg, &signature.0.into())]);

    ml.final_exponentiation() == Gt::identity()
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
#[cfg(feature = "pairing")]
pub fn verify_aggregated(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    #[cfg(feature = "multicore")]
    let hashes: Vec<_> = messages.par_iter().map(|msg| hash(msg)).collect();

    #[cfg(not(feature = "multicore"))]
    let hashes: Vec<_> = messages.iter().map(|msg| hash(msg)).collect();

    verify(signature, &hashes, public_keys)
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
#[cfg(all(feature = "blst", feature = "multicore"))]
pub fn verify_aggregated(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    use blst_lib::BLST_ERROR;

    if messages.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_messages = messages.len();

    if n_messages != public_keys.len() {
        return false;
    }

    // zero key & single message should fail
    if n_messages == 1 && public_keys[0].0.is_identity().into() {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    if !blstrs::unique_messages(messages) {
        return false;
    }

    let n_workers = std::cmp::min(rayon::current_num_threads(), n_messages);
    let Some(Ok(acc)) = messages
        .par_iter()
        .zip(public_keys.par_iter())
        .chunks(n_messages / n_workers)
        .map(|chunk| -> Result<_, BLST_ERROR> {
            let mut pairing = blstrs::PairingG1G2::new(true, CSUITE);

            for (message, public_key) in chunk {
                pairing.aggregate(&public_key.0.into(), None, message, &[])?;
            }
            pairing.commit();
            Ok(pairing)
        })
        .try_reduce_with(|mut acc, pairing| -> Result<_, BLST_ERROR> {
            acc.merge(&pairing)?;
            Ok(acc)
        })
    else {
        return false;
    };

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &signature.0);
    acc.finalverify(Some(&gtsig))
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
#[cfg(all(feature = "blst", not(feature = "multicore")))]
pub fn verify_aggregated(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    if messages.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_messages = messages.len();

    if n_messages != public_keys.len() {
        return false;
    }

    // zero key & single message should fail
    if n_messages == 1 && public_keys[0].0.is_identity().into() {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    if !blstrs::unique_messages(messages) {
        return false;
    }

    let mut pairing = blstrs::PairingG1G2::new(true, CSUITE);
    for (message, public_key) in messages.iter().zip(public_keys.iter()) {
        if pairing
            .aggregate(&public_key.0.into(), None, message, &[])
            .is_err()
        {
            return false;
        }
        pairing.commit();
    }

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &signature.0);

    pairing.finalverify(Some(&gtsig))
}

/// Verifies the aggregated signature from the same message
/// Using aggregated public key to speed up verification
#[cfg(feature = "pairing")]
pub fn fast_verify_aggregated(
    signature: &Signature,
    message: &[u8],
    public_keys: &[PublicKey],
) -> bool {
    use bls12_381::G1Projective;

    if public_keys.is_empty() {
        return false;
    }

    if public_keys.iter().any(|pk| pk.0.is_identity().into()) {
        return false;
    }

    #[cfg(feature = "multicore")]
    let aggregated_pk = public_keys
        .par_iter()
        .fold(G1Projective::identity, |mut acc, pk| {
            acc += &pk.0;
            acc
        })
        .reduce(G1Projective::identity, |acc, val| acc + val);

    #[cfg(not(feature = "multicore"))]
    let aggregated_pk = public_keys
        .iter()
        .fold(G1Projective::identity(), |acc, pk| acc + pk.0);

    let aggregated_pk_affine = G1Affine::from(aggregated_pk);
    let message_hash = hash(message);
    let message_hash_affine = G2Affine::from(message_hash);

    // Verify: e(aggregated_pk, H(m)) == e(g1, signature)
    let lhs = Bls12::multi_miller_loop(&[(&aggregated_pk_affine, &message_hash_affine.into())]);
    let g1_neg = -G1Affine::generator();
    let rhs = Bls12::multi_miller_loop(&[(&g1_neg, &signature.0.into())]);

    let ml = lhs + rhs;
    ml.final_exponentiation() == Gt::identity()
}

/// Verifies the aggregated signature from the same message
/// Using aggregated public key to speed up verification
#[cfg(feature = "blst")]
pub fn fast_verify_aggregated(
    signature: &Signature,
    message: &[u8],
    public_keys: &[PublicKey],
) -> bool {
    if public_keys.is_empty() {
        return false;
    }

    // Zero keys should always fail
    if public_keys.iter().any(|pk| pk.0.is_identity().into()) {
        return false;
    }

    #[cfg(feature = "multicore")]
    let aggregated_pk = public_keys
        .par_iter()
        .fold(blstrs::G1Projective::identity, |mut acc, pk| {
            acc += &pk.0;
            acc
        })
        .reduce(blstrs::G1Projective::identity, |acc, val| acc + val);

    #[cfg(not(feature = "multicore"))]
    let aggregated_pk = public_keys
        .iter()
        .fold(blstrs::G1Projective::identity(), |acc, pk| acc + pk.0);

    // Use BLST's optimized same-message verification
    let mut pairing = blstrs::PairingG1G2::new(true, CSUITE);
    let aggregated_pk_affine = blstrs::G1Affine::from(aggregated_pk);

    if pairing
        .aggregate(&aggregated_pk_affine, None, message, &[])
        .is_err()
    {
        return false;
    }
    pairing.commit();

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &signature.0);

    pairing.finalverify(Some(&gtsig))
}

/// Generate a Proof of Possession for the given private key.
/// PoP = Sign(private_key, public_key)
/// The message being signed is the public key itself in compressed format.
#[cfg(feature = "pairing")]
pub fn pop_prove(private_key: &PrivateKey) -> ProofOfPossession {
    let public_key = private_key.public_key();
    let pk_bytes = public_key.as_bytes();

    // Hash the public key using PoP ciphersuite
    let message_hash = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        &pk_bytes,
        BLS_POP_CIPHERSUITE,
    );

    // Sign: signature = private_key * H(public_key)
    let signature = message_hash * private_key.0;

    signature.into()
}

/// Generate a Proof of Possession for the given private key.
/// PoP = Sign(private_key, public_key)
/// The message being signed is the public key itself in compressed format.
#[cfg(feature = "blst")]
pub fn pop_prove(private_key: &PrivateKey) -> ProofOfPossession {
    let public_key = private_key.public_key();
    let pk_bytes = public_key.as_bytes();

    // Hash the public key using PoP ciphersuite
    let message_hash = G2Projective::hash_to_curve(&pk_bytes, BLS_POP_CIPHERSUITE, &[]);

    // Sign: signature = private_key * H(public_key)
    let signature = message_hash * private_key.0;

    signature.into()
}

/// Verify a Proof of Possession for the given public key.
/// Verify that: e(public_key, H(public_key)) == e(g1, pop)
/// This proves that the holder of the public key knows the corresponding private key.
#[cfg(feature = "pairing")]
pub fn pop_verify(pop: &ProofOfPossession, public_key: &PublicKey) -> bool {
    // Zero key should always fail
    if public_key.0.is_identity().into() {
        return false;
    }

    let pk_bytes = public_key.as_bytes();
    let message_hash = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        &pk_bytes,
        BLS_POP_CIPHERSUITE,
    );
    let message_hash_affine = G2Affine::from(message_hash);
    let pk_affine = public_key.as_affine();

    // Verify: e(pk, H(pk)) == e(g1, pop)
    let lhs = Bls12::multi_miller_loop(&[(&pk_affine, &message_hash_affine.into())]);
    let g1_neg = -G1Affine::generator();
    let rhs = Bls12::multi_miller_loop(&[(&g1_neg, &pop.0.into())]);

    let ml = lhs + rhs;
    ml.final_exponentiation() == Gt::identity()
}

/// Verify a Proof of Possession for the given public key.
/// Verify that: e(public_key, H(public_key)) == e(g1, pop)
/// This proves that the holder of the public key knows the corresponding private key.
#[cfg(feature = "blst")]
pub fn pop_verify(pop: &ProofOfPossession, public_key: &PublicKey) -> bool {
    // Zero key should always fail
    if public_key.0.is_identity().into() {
        return false;
    }

    let pk_bytes = public_key.as_bytes();

    // Use BLST's optimized verification
    let mut pairing = blstrs::PairingG1G2::new(true, BLS_POP_CIPHERSUITE);

    if pairing
        .aggregate(&public_key.0.into(), None, &pk_bytes, &[])
        .is_err()
    {
        return false;
    }
    pairing.commit();

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &pop.0);

    pairing.finalverify(Some(&gtsig))
}

/// Batch verify multiple Proofs of Possession.
/// This is more efficient than verifying each PoP individually.
#[cfg(feature = "pairing")]
pub fn pop_verify_batch(pops: &[ProofOfPossession], public_keys: &[PublicKey]) -> bool {
    if pops.is_empty() || public_keys.is_empty() || pops.len() != public_keys.len() {
        return false;
    }

    // Zero keys should always fail
    if public_keys.iter().any(|pk| pk.0.is_identity().into()) {
        return false;
    }

    // Compute hashes for all public keys
    #[cfg(feature = "multicore")]
    let hashes: Vec<_> = public_keys
        .par_iter()
        .map(|pk| {
            let pk_bytes = pk.as_bytes();
            <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                &pk_bytes,
                BLS_POP_CIPHERSUITE,
            )
        })
        .collect();

    #[cfg(not(feature = "multicore"))]
    let hashes: Vec<_> = public_keys
        .iter()
        .map(|pk| {
            let pk_bytes = pk.as_bytes();
            <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                &pk_bytes,
                BLS_POP_CIPHERSUITE,
            )
        })
        .collect();

    // Aggregate all PoPs
    #[cfg(feature = "multicore")]
    let aggregated_pop = pops
        .par_iter()
        .fold(G2Projective::identity, |mut acc, pop| {
            acc += &pop.0;
            acc
        })
        .reduce(G2Projective::identity, |acc, val| acc + val);

    #[cfg(not(feature = "multicore"))]
    let aggregated_pop = pops
        .iter()
        .fold(G2Projective::identity(), |acc, pop| acc + pop.0);

    // Use the existing verify function
    let pop_signature = Signature(aggregated_pop.into());
    verify(&pop_signature, &hashes, public_keys)
}

/// Batch verify multiple Proofs of Possession.
/// This is more efficient than verifying each PoP individually.
#[cfg(feature = "blst")]
pub fn pop_verify_batch(pops: &[ProofOfPossession], public_keys: &[PublicKey]) -> bool {
    if pops.is_empty() || public_keys.is_empty() || pops.len() != public_keys.len() {
        return false;
    }

    // Zero keys should always fail
    if public_keys.iter().any(|pk| pk.0.is_identity().into()) {
        return false;
    }

    let mut pairing = blstrs::PairingG1G2::new(true, BLS_POP_CIPHERSUITE);

    for public_key in public_keys {
        let pk_bytes = public_key.as_bytes();
        if pairing
            .aggregate(&public_key.0.into(), None, &pk_bytes, &[])
            .is_err()
        {
            return false;
        }
    }
    pairing.commit();
    // Aggregate all PoPs
    #[cfg(feature = "multicore")]
    let aggregated_pop = pops
        .par_iter()
        .fold(G2Projective::identity, |mut acc, pop| {
            acc += &pop.0;
            acc
        })
        .reduce(G2Projective::identity, |acc, val| acc + val);

    #[cfg(not(feature = "multicore"))]
    let aggregated_pop = pops
        .iter()
        .fold(G2Projective::identity(), |acc, pop| acc + pop.0);

    let mut gtsig = Gt::default();
    blstrs::PairingG1G2::aggregated(&mut gtsig, &G2Affine::from(aggregated_pop));

    pairing.finalverify(Some(&gtsig))
}

/* Serialize and Deserialize for Signature and ProofOfPossession */

impl SerdeSerialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.as_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> SerdeDeserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let bytes = hex::decode(&hex_str)
                .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
            Signature::from_bytes(&bytes)
                .map_err(|e| serde::de::Error::custom(format!("Invalid signature: {:?}", e)))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Signature::from_bytes(&bytes)
                .map_err(|e| serde::de::Error::custom(format!("Invalid signature: {:?}", e)))
        }
    }
}

impl Encode for Signature {
    fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
        let bytes = self.as_bytes();
        dest.write(&bytes);
    }

    fn size_hint(&self) -> usize {
        G2_COMPRESSED_SIZE
    }
}

impl Decode for Signature {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut bytes = [0u8; G2_COMPRESSED_SIZE];
        input.read(&mut bytes)?;
        Signature::from_bytes(&bytes).map_err(|_| codec::Error::from("Invalid Signature bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use serde::Deserialize;

    #[cfg(feature = "pairing")]
    use crate::key::G1_COMPRESSED_SIZE;
    #[cfg(feature = "pairing")]
    use bls12_381::{G1Projective, Scalar};
    #[cfg(feature = "blst")]
    use blstrs::{G1Projective, Scalar};

    #[test]
    fn basic_aggregation() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        let num_messages = 10;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        // generate messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| (0..64).map(|_| rng.random()).collect())
            .collect();

        // sign messages
        let sigs = messages
            .iter()
            .zip(&private_keys)
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

        let hashes = messages
            .iter()
            .map(|message| hash(message))
            .collect::<Vec<_>>();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();

        assert!(
            verify(&aggregated_signature, &hashes, &public_keys),
            "failed to verify"
        );

        let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
        assert!(verify_aggregated(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));
    }

    #[test]
    fn aggregation_same_messages() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        let num_messages = 10;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        // generate messages
        let message: Vec<u8> = (0..64).map(|_| rng.random()).collect();

        // sign messages
        let sigs = private_keys
            .iter()
            .map(|pk| pk.sign(&message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

        // check that equal messages can not be aggreagated
        let hashes: Vec<_> = (0..num_messages).map(|_| hash(&message)).collect();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();
        assert!(
            !verify(&aggregated_signature, &hashes, &public_keys),
            "must not verify aggregate with the same messages"
        );
        let messages = vec![&message[..]; num_messages];

        assert!(!verify_aggregated(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));
    }

    #[test]
    fn proof_of_possession_blocks_the_classic_rogue_key_attack() {
        let honest_secret = PrivateKey::new([11u8; 32]);
        let attacker_aggregate_secret = PrivateKey::new([22u8; 32]);
        let honest_public = honest_secret.public_key();
        let attacker_aggregate_public = attacker_aggregate_secret.public_key();

        // Registering R = attacker_pk - honest_pk makes the aggregated public key equal to the
        // attacker's known key. Without PoP admission the attacker can therefore forge a same-
        // message aggregate signature without the honest validator signing anything.
        let rogue_public = PublicKey(
            G1Projective::from(attacker_aggregate_public) - G1Projective::from(honest_public),
        );
        let message = b"sc-consensus-hotstuff rogue-key regression";
        let forged_aggregate = attacker_aggregate_secret.sign(message);
        assert!(fast_verify_aggregated(
            &forged_aggregate,
            message,
            &[honest_public, rogue_public],
        ));

        // The attacker can prove possession of attacker_aggregate_public, but not of R.
        let attacker_pop = pop_prove(&attacker_aggregate_secret);
        assert!(!pop_verify(&attacker_pop, &rogue_public));
    }

    #[test]
    fn test_zero_key() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        // In the current iteration we expect the zero key to be valid and work.
        let zero_key: PrivateKey = Scalar::ZERO.into();
        assert!(bool::from(zero_key.public_key().0.is_identity()));

        println!(
            "{:?}\n{:?}",
            zero_key.public_key().as_bytes(),
            zero_key.as_bytes()
        );
        let num_messages = 10;

        // generate private keys
        let mut private_keys: Vec<_> = (0..num_messages - 1)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        private_keys.push(zero_key);

        // generate messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| (0..64).map(|_| rng.random()).collect())
            .collect();

        // sign messages
        let sigs = messages
            .iter()
            .zip(&private_keys)
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

        let hashes = messages
            .iter()
            .map(|message| hash(message))
            .collect::<Vec<_>>();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();

        assert!(
            !verify(&aggregated_signature, &hashes, &public_keys),
            "verified with zero key"
        );

        let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
        assert!(!verify_aggregated(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));

        // single message is rejected
        let signature = zero_key.sign(&messages[0]);

        assert!(!zero_key.public_key().verify(signature, &messages[0]));

        let aggregated_signature = aggregate(&[signature][..]).expect("failed to aggregate");
        assert!(!verify_aggregated(
            &aggregated_signature,
            &messages[..1],
            &[zero_key.public_key()][..],
        ));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);
        let sk = PrivateKey::generate(&mut rng);

        let msg = (0..64).map(|_| rng.random()).collect::<Vec<u8>>();
        let signature = sk.sign(&msg);

        let signature_bytes = signature.as_bytes();
        assert_eq!(signature_bytes.len(), 96);
        assert_eq!(Signature::from_bytes(&signature_bytes).unwrap(), signature);
    }

    base64_serde_type!(Base64Standard, BASE64_STANDARD);

    #[derive(Debug, Clone, Deserialize)]
    struct Case {
        #[serde(rename = "Msg")]
        msg: String,
        #[serde(rename = "Ciphersuite")]
        ciphersuite: String,
        #[serde(rename = "G1Compressed", with = "Base64Standard")]
        g1_compressed: Vec<u8>,
        #[serde(rename = "G2Compressed", with = "Base64Standard")]
        g2_compressed: Vec<u8>,
        #[serde(rename = "BLSPrivKey")]
        priv_key: Option<String>,
        #[serde(rename = "BLSPubKey")]
        pub_key: Option<String>,
        #[serde(rename = "BLSSigG2")]
        signature: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct Cases {
        cases: Vec<Case>,
    }

    fn g1_from_slice(raw: &[u8]) -> Result<G1Affine, Error> {
        if raw.len() != G1_COMPRESSED_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; G1_COMPRESSED_SIZE];
        res.as_mut().copy_from_slice(raw);

        Option::from(G1Affine::from_compressed(&res)).ok_or(Error::GroupDecode)
    }

    #[cfg(feature = "pairing")]
    fn hash_to_g1(msg: &[u8], suite: &[u8]) -> G1Projective {
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, suite)
    }
    #[cfg(feature = "blst")]
    fn hash_to_g1(msg: &[u8], suite: &[u8]) -> G1Projective {
        G1Projective::hash_to_curve(msg, suite, &[])
    }

    #[cfg(feature = "pairing")]
    fn hash_to_g2(msg: &[u8], suite: &[u8]) -> G2Projective {
        <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, suite)
    }
    #[cfg(feature = "blst")]
    fn hash_to_g2(msg: &[u8], suite: &[u8]) -> G2Projective {
        G2Projective::hash_to_curve(msg, suite, &[])
    }

    #[test]
    fn test_vectors() {
        let cases: Cases =
            serde_json::from_slice(&std::fs::read("./tests/data.json").unwrap()).unwrap();

        for case in cases.cases {
            let g1: G1Projective = g1_from_slice(&case.g1_compressed).unwrap().into();

            assert_eq!(
                g1,
                hash_to_g1(case.msg.as_bytes(), case.ciphersuite.as_bytes())
            );

            let g2: G2Projective = g2_from_slice(&case.g2_compressed).unwrap().into();
            assert_eq!(
                g2,
                hash_to_g2(case.msg.as_bytes(), case.ciphersuite.as_bytes())
            );

            if case.ciphersuite.as_bytes() == CSUITE {
                let pub_key = PublicKey::from_bytes(
                    &BASE64_STANDARD
                        .decode(case.pub_key.as_ref().unwrap())
                        .unwrap(),
                )
                .unwrap();
                let priv_key = PrivateKey::from_string(case.priv_key.as_ref().unwrap()).unwrap();
                let signature = Signature::from_bytes(
                    &BASE64_STANDARD
                        .decode(case.signature.as_ref().unwrap())
                        .unwrap(),
                )
                .unwrap();

                let sig2 = priv_key.sign(&case.msg);
                assert_eq!(signature, sig2, "signatures do not match");

                assert!(pub_key.verify(signature, &case.msg), "failed to verify");
            }
        }
    }

    #[test]
    fn test_same_message_verification() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let num_signers = 5;

        // Generate private keys
        let private_keys: Vec<_> = (0..num_signers)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        // Same message for all signers
        let message: Vec<u8> = (0..32).map(|_| rng.random()).collect();

        // Sign the same message with different keys
        let signatures: Vec<_> = private_keys.iter().map(|sk| sk.sign(&message)).collect();

        // Aggregate signatures
        let aggregated_signature = aggregate(&signatures).expect("failed to aggregate");

        let public_keys: Vec<_> = private_keys.iter().map(|sk| sk.public_key()).collect();

        // Test fast same-message verification
        assert!(fast_verify_aggregated(
            &aggregated_signature,
            &message,
            &public_keys
        ));

        // Test with wrong message
        let wrong_message: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        assert!(!fast_verify_aggregated(
            &aggregated_signature,
            &wrong_message,
            &public_keys
        ));
    }

    #[test]
    fn test_verify_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate a private key
        let private_key = PrivateKey::generate(&mut rng);
        let public_key = private_key.public_key();

        // Generate a random message
        let message: Vec<u8> = (0..32).map(|_| rng.random()).collect();

        // Sign the message
        let signature = private_key.sign(&message);

        // Verify using core_verify
        assert!(verify_one(&signature, &message, &public_key));

        // Test with wrong message
        let wrong_message: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        assert!(!verify_one(&signature, &wrong_message, &public_key));

        // Test with wrong public key
        let wrong_private_key = PrivateKey::generate(&mut rng);
        let wrong_public_key = wrong_private_key.public_key();
        assert!(!verify_one(&signature, &message, &wrong_public_key));
    }

    #[test]
    fn test_verify_one_zero_key() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Create zero key
        let zero_key: PrivateKey = Scalar::ZERO.into();
        let zero_public_key = zero_key.public_key();

        let message: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        let signature = zero_key.sign(&message);

        // Zero key should always fail verification
        assert!(!verify_one(&signature, &message, &zero_public_key));
    }

    #[test]
    fn test_verify_one_consistency_with_existing() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let private_key = PrivateKey::generate(&mut rng);
        let public_key = private_key.public_key();
        let message: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        let signature = private_key.sign(&message);

        // core_verify should be consistent with public_key.verify
        let core_result = verify_one(&signature, &message, &public_key);
        let pk_result = public_key.verify(signature, &message);

        assert_eq!(
            core_result, pk_result,
            "verify_one and PublicKey::verify should give same result"
        );

        // Also test with aggregated signature of single signature
        let aggregated = aggregate(&[signature]).unwrap();
        let messages = vec![&message[..]];
        let public_keys = vec![public_key];

        let verify_messages_result = verify_aggregated(&aggregated, &messages, &public_keys);
        assert_eq!(
            core_result, verify_messages_result,
            "verify_one should be consistent with verify_messages for single signature"
        );
    }

    #[test]
    fn test_pop_prove_and_verify() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate a private key
        let private_key = PrivateKey::generate(&mut rng);
        let public_key = private_key.public_key();

        // Generate PoP
        let pop = pop_prove(&private_key);

        // Verify PoP
        assert!(pop_verify(&pop, &public_key));

        // Test with wrong public key
        let wrong_private_key = PrivateKey::generate(&mut rng);
        let wrong_public_key = wrong_private_key.public_key();
        assert!(!pop_verify(&pop, &wrong_public_key));
    }

    #[test]
    fn test_pop_zero_key() {
        // Create zero key
        let zero_key: PrivateKey = Scalar::ZERO.into();
        let zero_public_key = zero_key.public_key();

        let pop = pop_prove(&zero_key);

        // Zero key should always fail verification
        assert!(!pop_verify(&pop, &zero_public_key));
    }

    #[test]
    fn test_pop_batch_verify() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let num_keys = 5;

        // Generate private keys
        let private_keys: Vec<_> = (0..num_keys)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        let public_keys: Vec<_> = private_keys.iter().map(|sk| sk.public_key()).collect();

        // Generate PoPs
        let pops: Vec<_> = private_keys.iter().map(|sk| pop_prove(sk)).collect();

        // Batch verify
        assert!(pop_verify_batch(&pops, &public_keys));

        // Test with one wrong PoP
        let wrong_private_key = PrivateKey::generate(&mut rng);
        let wrong_pop = pop_prove(&wrong_private_key);
        let mut wrong_pops = pops.clone();
        wrong_pops[0] = wrong_pop;

        assert!(!pop_verify_batch(&wrong_pops, &public_keys));
    }

    #[test]
    fn test_pop_serialization() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let private_key = PrivateKey::generate(&mut rng);

        let pop = pop_prove(&private_key);

        // Test serialization roundtrip
        let pop_bytes = pop.as_bytes();
        assert_eq!(pop_bytes.len(), G2_COMPRESSED_SIZE);

        let pop_deserialized = ProofOfPossession::from_bytes(&pop_bytes).unwrap();
        assert_eq!(pop, pop_deserialized);
    }

    #[test]
    fn test_pop_different_from_signature() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let private_key = PrivateKey::generate(&mut rng);
        let public_key = private_key.public_key();

        // Generate PoP
        let pop = pop_prove(&private_key);

        // Generate regular signature of the same public key
        let pk_bytes = public_key.as_bytes();
        let signature = private_key.sign(&pk_bytes);

        // PoP and regular signature should be different
        // (because they use different ciphersuites)
        assert_ne!(pop.0.to_compressed(), signature.0.to_compressed());
    }
}

#[cfg(test)]
mod serde_tests {
    use super::*;
    use codec::{Decode, Encode};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use serde_json;

    #[test]
    fn test_signature_serde_json_roundtrip() {
        let rng = &mut ChaCha8Rng::seed_from_u64(42);
        let sk = PrivateKey::generate(rng);
        let message = b"test message";
        let signature = sk.sign(message);

        let json = serde_json::to_string(&signature).expect("Failed to serialize to JSON");
        println!("Signature JSON: {}", json);

        let signature_restored: Signature =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");

        assert_eq!(signature, signature_restored);
        assert_eq!(signature.as_bytes(), signature_restored.as_bytes());
    }

    #[test]
    fn test_signature_codec_roundtrip() {
        let rng = &mut ChaCha8Rng::seed_from_u64(456);
        let sk = PrivateKey::generate(rng);
        let message = b"test message";
        let signature = sk.sign(message);

        let encoded = signature.encode();
        println!("Signature codec encoded length: {} bytes", encoded.len());

        let signature_restored =
            Signature::decode(&mut &encoded[..]).expect("Failed to decode with codec");

        assert_eq!(signature, signature_restored);
        assert_eq!(signature.as_bytes(), signature_restored.as_bytes());
    }

    #[test]
    fn test_signature_hex_format() {
        let rng = &mut ChaCha8Rng::seed_from_u64(789);
        let sk = PrivateKey::generate(rng);
        let message = b"test message";
        let signature = sk.sign(message);

        let json = serde_json::to_string(&signature).expect("Failed to serialize to JSON");
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));

        let hex_str = &json[1..json.len() - 1];
        assert_eq!(hex_str.len(), 192);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

        let expected_hex = hex::encode(signature.as_bytes());
        assert_eq!(hex_str, expected_hex);
    }

    #[test]
    fn test_pop_serde_json_roundtrip() {
        let rng = &mut ChaCha8Rng::seed_from_u64(42);
        let sk = PrivateKey::generate(rng);
        let pop = pop_prove(&sk);

        let json = serde_json::to_string(&pop).expect("Failed to serialize to JSON");
        println!("ProofOfPossession JSON: {}", json);

        let pop_restored: ProofOfPossession =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");

        assert_eq!(pop, pop_restored);
        assert_eq!(pop.as_bytes(), pop_restored.as_bytes());
    }

    #[test]
    fn test_pop_codec_roundtrip() {
        let rng = &mut ChaCha8Rng::seed_from_u64(456);
        let sk = PrivateKey::generate(rng);
        let pop = pop_prove(&sk);

        let encoded = pop.encode();
        println!(
            "ProofOfPossession codec encoded length: {} bytes",
            encoded.len()
        );

        let pop_restored =
            ProofOfPossession::decode(&mut &encoded[..]).expect("Failed to decode with codec");

        assert_eq!(pop, pop_restored);
        assert_eq!(pop.as_bytes(), pop_restored.as_bytes());
    }

    #[test]
    fn test_size_hints() {
        let rng = &mut ChaCha8Rng::seed_from_u64(2222);
        let sk = PrivateKey::generate(rng);
        let message = b"test message";
        let signature = sk.sign(message);
        let pop = pop_prove(&sk);

        assert_eq!(signature.size_hint(), G2_COMPRESSED_SIZE);
        assert_eq!(pop.size_hint(), G2_COMPRESSED_SIZE);

        let sig_encoded = signature.encode();
        let pop_encoded = pop.encode();
        assert_eq!(sig_encoded.len(), G2_COMPRESSED_SIZE);
        assert_eq!(pop_encoded.len(), G2_COMPRESSED_SIZE);
    }

    #[test]
    fn test_invalid_hex_deserialization() {
        let invalid_hex = "\"invalid_hex_string\"";
        let result: Result<Signature, _> = serde_json::from_str(invalid_hex);
        assert!(result.is_err());

        let result: Result<ProofOfPossession, _> = serde_json::from_str(invalid_hex);
        assert!(result.is_err());

        let wrong_length_hex = format!("\"{}\"", "a".repeat(190)); // 190 characters instead of 192
        let result: Result<Signature, _> = serde_json::from_str(&wrong_length_hex);
        assert!(result.is_err());

        let result: Result<ProofOfPossession, _> = serde_json::from_str(&wrong_length_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_formats_consistency() {
        let rng = &mut ChaCha8Rng::seed_from_u64(999);
        let sk = PrivateKey::generate(rng);
        let message = b"test message";
        let original_sig = sk.sign(message);
        let original_pop = pop_prove(&sk);

        let sig_bytes = original_sig.as_bytes();
        let sig_from_custom = Signature::from_bytes(&sig_bytes).unwrap();
        let sig_json = serde_json::to_string(&original_sig).unwrap();
        let sig_from_json: Signature = serde_json::from_str(&sig_json).unwrap();
        let sig_encoded = original_sig.encode();
        let sig_from_codec = Signature::decode(&mut &sig_encoded[..]).unwrap();

        assert_eq!(original_sig, sig_from_custom);
        assert_eq!(original_sig, sig_from_json);
        assert_eq!(original_sig, sig_from_codec);

        let pop_bytes = original_pop.as_bytes();
        let pop_from_custom = ProofOfPossession::from_bytes(&pop_bytes).unwrap();
        let pop_json = serde_json::to_string(&original_pop).unwrap();
        let pop_from_json: ProofOfPossession = serde_json::from_str(&pop_json).unwrap();
        let pop_encoded = original_pop.encode();
        let pop_from_codec = ProofOfPossession::decode(&mut &pop_encoded[..]).unwrap();

        assert_eq!(original_pop, pop_from_custom);
        assert_eq!(original_pop, pop_from_json);
        assert_eq!(original_pop, pop_from_codec);
    }
}
