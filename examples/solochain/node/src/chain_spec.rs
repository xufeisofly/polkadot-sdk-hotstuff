use sc_service::ChainType;
use solochain_template_runtime::WASM_BINARY;
use sp_consensus_hotstuff::{
    AuthorityDiscoveryId, AuthorityId, BlsPublicBytes, BlsSignatureBytes, SessionKeys,
};
use sp_core::Pair;

pub type ChainSpec = sc_service::GenericChainSpec;

/// Deterministic development credentials. Never use these on a public network.
fn local_spec(names: &[&str], id: &str) -> Result<ChainSpec, String> {
    let mut authorities = Vec::new();
    let mut keys = Vec::new();
    let mut balances = Vec::new();
    for name in names {
        let seed = format!("//{name}");
        let account: sp_core::crypto::AccountId32 =
            sp_core::sr25519::Pair::from_string(&seed, None)
                .unwrap()
                .public()
                .into();
        let auth: AuthorityId = sp_core::ed25519::Pair::from_string(&seed, None)
            .unwrap()
            .public()
            .into();
        let auth_disc: AuthorityDiscoveryId = sp_core::sr25519::Pair::from_string(&seed, None)
            .unwrap()
            .public()
            .into();
        let private =
            sc_consensus_hotstuff_bls::PrivateKey::new(sp_io::hashing::blake2_256(seed.as_bytes()));
        let bls_pk = BlsPublicBytes::try_from(private.public_key()).unwrap();
        let pop =
            BlsSignatureBytes::try_from(sc_consensus_hotstuff_bls::pop_prove(&private)).unwrap();
        authorities.push((
            account.clone(),
            auth.clone(),
            bls_pk,
            pop,
            auth_disc.clone(),
        ));
        keys.push((
            account.clone(),
            account.clone(),
            SessionKeys {
                auth,
                bls_pk,
                auth_disc,
            },
        ));
        balances.push((account, 1u128 << 60));
    }
    let root = balances[0].0.clone();
    Ok(
        ChainSpec::builder(WASM_BINARY.ok_or("Runtime Wasm not built")?, None)
            .with_name("Hotstuff Local Testnet")
            .with_id(id)
            .with_chain_type(ChainType::Local)
            .with_protocol_id("hotstuff-example")
            .with_genesis_config_patch(serde_json::json!({
                "balances": { "balances": balances }, "sudo": { "key": root },
                "hotstuff": { "initialAuthorities": authorities },
                "session": { "keys": keys }
            }))
            .build(),
    )
}
pub fn development_chain_spec() -> Result<ChainSpec, String> {
    local_spec(&["Alice"], "dev")
}
pub fn local_chain_spec() -> Result<ChainSpec, String> {
    local_spec(&["Alice", "Bob", "Charlie", "Dave"], "hotstuff_local")
}
