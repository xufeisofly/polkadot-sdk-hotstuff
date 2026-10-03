use crate::key::{PublicKey, Serialize};
use crate::signature::Signature;
use sp_consensus_hotstuff::{BlsPublicBytes, BlsSignatureBytes};

#[cfg(feature = "std")]
impl From<BlsPublicBytes> for PublicKey {
    fn from(value: BlsPublicBytes) -> Self {
        PublicKey::from_bytes(value.as_ref()).expect("BlsPublicBytes always 48B")
    }
}

#[cfg(feature = "std")]
impl TryFrom<PublicKey> for BlsPublicBytes {
    type Error = ();
    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if bytes.len() == 48 {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&bytes);
            Ok(BlsPublicBytes::new(arr))
        } else {
            Err(())
        }
    }
}

#[cfg(feature = "std")]
impl From<BlsSignatureBytes> for Signature {
    fn from(value: BlsSignatureBytes) -> Self {
        Signature::from_bytes(value.as_ref()).expect("BlsPublicBytes always 96B")
    }
}

#[cfg(feature = "std")]
impl TryFrom<Signature> for BlsSignatureBytes {
    type Error = ();
    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if bytes.len() == 96 {
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&bytes);
            Ok(BlsSignatureBytes::new(arr))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use crate::key::PrivateKey;
    use crate::signature::pop_prove;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sp_consensus_hotstuff::{verify_bls_pop, BlsPublicBytes, BlsSignatureBytes};

    /// Test conversion between PublicKey and BlsPublicBytes and back
    #[test]
    fn test_public_key_bls_public_bytes_roundtrip() {
        // Generate a valid PublicKey from PrivateKey
        let rng = &mut ChaCha8Rng::seed_from_u64(42);
        let sk = PrivateKey::generate(rng);
        let pk = sk.public_key();

        // PublicKey -> BlsPublicBytes
        let bls_bytes = BlsPublicBytes::try_from(pk).expect("Conversion should succeed");

        // BlsPublicBytes -> PublicKey
        let pk2 = PublicKey::from(bls_bytes);

        // The byte content should be equal
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
    }

    /// Test conversion between Signature and BlsSignatureBytes and back
    #[test]
    fn test_signature_bls_signature_bytes_roundtrip() {
        // Generate a valid Signature from PrivateKey
        let rng = &mut ChaCha8Rng::seed_from_u64(77);
        let sk = PrivateKey::generate(rng);
        let sig = sk.sign(b"test message");

        // Signature -> BlsSignatureBytes
        let sig_bytes = BlsSignatureBytes::try_from(sig).expect("Conversion should succeed");

        // BlsSignatureBytes -> Signature
        let sig2 = Signature::from(sig_bytes);

        // The byte content should be equal
        assert_eq!(sig.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn generated_pop_is_accepted_by_runtime_verifier() {
        let private_key = PrivateKey::new([42u8; 32]);
        let public_key = BlsPublicBytes::try_from(private_key.public_key()).unwrap();
        let pop = BlsSignatureBytes::try_from(pop_prove(&private_key)).unwrap();
        assert!(verify_bls_pop(&public_key, &pop));

        let other_key = PrivateKey::new([43u8; 32]);
        let other_public_key = BlsPublicBytes::try_from(other_key.public_key()).unwrap();
        assert!(!verify_bls_pop(&other_public_key, &pop));

        let mut tampered = [0u8; 96];
        tampered.copy_from_slice(pop.as_slice());
        tampered[95] ^= 1;
        assert!(!verify_bls_pop(
            &public_key,
            &BlsSignatureBytes::new(tampered),
        ));
    }
}
