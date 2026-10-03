# sc-consensus-hotstuff-bls

BLS12-381 signing, aggregation, proof of possession, and local keystore support for Hotstuff consensus. Uses the blst backend by default; the pairing feature supplies a pure Rust compatibility backend.

See [keygen](examples/keygen.rs) for private-key provisioning and [integration](../docs/integration.md) for session admission. Inherited crypto code retains its MIT OR Apache-2.0 license.
