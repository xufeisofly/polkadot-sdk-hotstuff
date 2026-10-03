use crate::key::*;
use crate::pair::*;
use crate::signature::*;
use rand::CryptoRng;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};

#[derive(Debug)]
pub enum Error {
    /// Keystore unavailable
    Unavailable,
    /// Programming errors
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Unavailable => fmt.write_str("Keystore unavailable"),
            Error::Other(error) => write!(fmt, "An unknown keystore error occurred: {}", error),
        }
    }
}

impl std::error::Error for Error {}

/// Keystore manages multiple bls key pairs
pub trait Keystore: Send + Sync {
    fn generate_new<R: CryptoRng>(&mut self, rng: &mut R) -> Result<PublicKey, Error>;
    fn import_from_seed(&mut self, seed: &Seed) -> Result<PublicKey, Error>;
    fn clear_pair(&mut self) -> Result<(), Error>;
    fn has_pair(&self) -> bool;
    fn reload_pair(&mut self) -> Result<Option<PublicKey>, Error>;

    /// sign with the sk who generated pk
    fn bls_sign(&self, msg: &[u8]) -> Result<Signature, Error>;
    fn bls_pop_prove(&self) -> Result<ProofOfPossession, Error>;
}

#[derive(Debug)]
pub struct SimpleKeystore {
    file_path: PathBuf,
    pair: Option<Pair>,
}

impl Keystore for SimpleKeystore {
    fn generate_new<R: CryptoRng>(&mut self, rng: &mut R) -> Result<PublicKey, Error> {
        let (pair, _, _) = Pair::generate_new(rng);
        let pk = pair.public();
        self.save_pair(&pair)?;
        self.pair = Some(pair);
        Ok(pk)
    }

    fn import_from_seed(&mut self, seed: &Seed) -> Result<PublicKey, Error> {
        let pair = Pair::new(seed);
        let pk = pair.public();
        self.save_pair(&pair)?;
        self.pair = Some(pair);
        Ok(pk)
    }

    fn clear_pair(&mut self) -> Result<(), Error> {
        self.pair = None;

        fs::remove_file(&self.file_path).ok();
        Ok(())
    }

    fn has_pair(&self) -> bool {
        self.pair.is_some()
    }

    fn reload_pair(&mut self) -> Result<Option<PublicKey>, Error> {
        if let Some(seed) = self.load_seed()? {
            let pair = Pair::new(&seed);
            let pk = pair.public();
            self.pair = Some(pair);
            Ok(Some(pk))
        } else {
            Ok(None)
        }
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        if let Some(pair) = self.pair.as_ref() {
            let sig = pair.sign(msg);
            Ok(sig)
        } else {
            Err(Error::Other("Sign failed".to_string()))
        }
    }

    fn bls_pop_prove(&self) -> Result<ProofOfPossession, Error> {
        if let Some(pair) = self.pair.as_ref() {
            let pop = pair.pop_prove();
            Ok(pop)
        } else {
            Err(Error::Other("PopProve failed".to_string()))
        }
    }
}

impl SimpleKeystore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            file_path: path.as_ref().to_path_buf(),
            pair: None,
        }
    }

    fn save_pair(&self, pair: &Pair) -> Result<(), Error> {
        atomic_write(&self.file_path, pair.seed.as_ref()).map_err(|e| Error::Other(e.to_string()))
    }

    fn load_seed(&self) -> Result<Option<Seed>, Error> {
        match fs::read(&self.file_path) {
            Ok(data) => {
                if data.len() == SEED_SIZE {
                    let mut seed_bytes = [0u8; SEED_SIZE];
                    seed_bytes.copy_from_slice(&data);
                    Ok(Some(Seed(seed_bytes)))
                } else {
                    Err(Error::Other("Invalid seed file format".to_string()))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }
}

fn atomic_write(path: &PathBuf, data: &[u8]) -> Result<(), std::io::Error> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_keystore() -> (SimpleKeystore, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("test_keystore.key");
        let keystore = SimpleKeystore::new(&keystore_path);
        (keystore, temp_dir)
    }

    #[test]
    fn test_new_keystore_has_no_pair() {
        let (keystore, _temp_dir) = create_test_keystore();
        assert!(!keystore.has_pair());
    }

    #[test]
    fn test_generate_new_key() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        let pk = keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");

        assert!(keystore.has_pair());
        assert_eq!(pk.as_bytes().len(), 48);
        assert!(keystore.file_path.exists());
    }

    #[test]
    fn test_import_from_seed() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let seed = Seed([1u8; 32]);

        let pk = keystore
            .import_from_seed(&seed)
            .expect("Failed to import seed");

        assert!(keystore.has_pair());
        assert_eq!(pk.as_bytes().len(), 48);

        let pair = Pair::new(&seed);
        assert_eq!(pk.as_bytes(), pair.public().as_bytes());
    }

    #[test]
    fn test_clear_pair() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");
        assert!(keystore.has_pair());
        assert!(keystore.file_path.exists());

        keystore.clear_pair().expect("Failed to clear pair");
        assert!(!keystore.has_pair());
        assert!(!keystore.file_path.exists());
    }

    #[test]
    fn test_reload_pair() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let seed = Seed([42u8; 32]);

        let original_pk = keystore
            .import_from_seed(&seed)
            .expect("Failed to import seed");

        keystore.pair = None;
        assert!(!keystore.has_pair());

        let reloaded_pk = keystore
            .reload_pair()
            .expect("Failed to reload")
            .expect("No key found after reload");

        assert!(keystore.has_pair());
        assert_eq!(original_pk.as_bytes(), reloaded_pk.as_bytes());
    }

    #[test]
    fn test_reload_nonexistent_pair() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        let result = keystore.reload_pair().expect("Reload should not error");
        assert!(result.is_none());
        assert!(!keystore.has_pair());
    }

    #[test]
    fn test_sign_message() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");

        let message = b"test message";
        let signature = keystore.bls_sign(message).expect("Failed to sign");

        assert_eq!(signature.as_bytes().len(), 96);
    }

    #[test]
    fn test_sign_no_key_no_file() {
        let (keystore, _temp_dir) = create_test_keystore();

        let message = b"test message";
        let result = keystore.bls_sign(message);

        assert!(result.is_err());
        if let Err(Error::Other(msg)) = result {
            assert_eq!(msg, "Sign failed");
        } else {
            panic!("Expected Error::Other");
        }
    }

    #[test]
    fn test_pop_prove() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");

        let pop = keystore.bls_pop_prove().expect("Failed to generate PoP");
        assert_eq!(pop.as_bytes().len(), 96);
    }

    #[test]
    fn test_persistence_across_instances() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("persistent_keystore.key");

        let original_pk = {
            let mut keystore1 = SimpleKeystore::new(&keystore_path);
            let mut rng = ChaCha8Rng::seed_from_u64(12);
            keystore1
                .generate_new(&mut rng)
                .expect("Failed to generate key")
        };

        let mut keystore2 = SimpleKeystore::new(&keystore_path);
        let reloaded_pk = keystore2
            .reload_pair()
            .expect("Failed to reload")
            .expect("No key found in new instance");

        assert_eq!(original_pk.as_bytes(), reloaded_pk.as_bytes());
    }

    #[test]
    fn test_file_permissions() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&keystore.file_path).expect("Failed to get file metadata");
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_atomic_write_consistency() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let seed1 = Seed([1u8; 32]);
        let seed2 = Seed([2u8; 32]);

        keystore
            .import_from_seed(&seed1)
            .expect("Failed to import first seed");

        keystore
            .import_from_seed(&seed2)
            .expect("Failed to import second seed");

        keystore.pair = None;
        let reloaded_pk = keystore
            .reload_pair()
            .expect("Failed to reload")
            .expect("No key found");

        let expected_pk = Pair::new(&seed2).public();
        assert_eq!(reloaded_pk.as_bytes(), expected_pk.as_bytes());
    }

    #[test]
    fn test_corrupted_file_handling() {
        let (mut keystore, _temp_dir) = create_test_keystore();

        fs::write(&keystore.file_path, b"corrupted_data").expect("Failed to write corrupted file");

        let result = keystore.reload_pair();
        assert!(result.is_err());
        if let Err(Error::Other(msg)) = result {
            assert_eq!(msg, "Invalid seed file format");
        } else {
            panic!("Expected Error::Other for corrupted file");
        }
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        use crate::signature::verify_one;

        let (mut keystore, _temp_dir) = create_test_keystore();
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        let public_key = keystore
            .generate_new(&mut rng)
            .expect("Failed to generate key");

        let message = b"Hello, BLS signature test!";

        let signature = keystore.bls_sign(message).expect("Failed to sign message");

        println!("Public key: {:?}", hex::encode(public_key.as_bytes()));
        println!("Message: {:?}", hex::encode(message));
        println!("Signature: {:?}", hex::encode(signature.as_bytes()));

        let verification_result = verify_one(&signature, message, &public_key);

        println!("Verification result: {}", verification_result);
        assert!(verification_result, "Signature verification should succeed");
    }
}
