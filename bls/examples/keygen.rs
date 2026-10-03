//! Generate a private BLS key file and the public admission proof. Never print the seed.
use codec::Encode;
use sc_consensus_hotstuff_bls::keystore::{Keystore, SimpleKeystore};
use sp_consensus_hotstuff::{BlsPublicBytes, BlsSignatureBytes, SessionKeysProof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: keygen <new-key-file>")?,
    );
    if path.exists() {
        return Err("refusing to overwrite an existing key".into());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut store = SimpleKeystore::new(&path);
    let public = BlsPublicBytes::try_from(store.generate_new(&mut rand::rng())?)
        .map_err(|_| "invalid public key")?;
    let pop = BlsSignatureBytes::try_from(store.bls_pop_prove()?).map_err(|_| "invalid PoP")?;
    println!(
        "{}",
        serde_json::json!({
            "blsPublic": format!("0x{}", hex::encode(public.as_ref())),
            "blsPop": format!("0x{}", hex::encode(pop.as_ref())),
            "sessionSetKeysProof": format!("0x{}", hex::encode(SessionKeysProof::V1 { bls_pop: pop }.encode())),
        })
    );
    Ok(())
}
