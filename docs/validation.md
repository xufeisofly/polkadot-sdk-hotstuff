# Validation results

Validated on 3 October 2026 with macOS 15.6.1 on Apple Silicon, Rust 1.95.0, and upstream Polkadot SDK release `polkadot-stable2606-2`. The build uses published upstream SDK crates, with exact versions locked in `Cargo.lock`.

## Build and unit tests

The native solochain node and its Wasm runtime built successfully with:

```bash
./scripts/cargo.sh build --locked -p solochain-template-node
./scripts/cargo.sh test --locked \
  -p sc-consensus-hotstuff -p sp-consensus-hotstuff \
  -p pallet-hotstuff -p sc-consensus-hotstuff-bls --lib
```

All 139 library tests passed: 76 client tests, 7 pallet tests, 52 BLS tests, and 4 primitives tests. These include certificate verification, BLS admission proofs, session rules, timeout broadcasts, deterministic bootstrap leader changes, canonical notification filtering, and single-signature aggregation for a one-validator chain. `cargo fmt --check` and locked workspace metadata validation also passed.

The BLS key-generation example produced a 32-byte private seed file with mode 0600, emitted public key/proof material, and refused to overwrite the existing private key. No private test key is published in this repository.

## Running chains

The README's development-chain commands finalized block 6 on a single validator. The multi-node test used four validators, a fresh full node, and a fresh warp node:

| Check | Observed result |
| --- | --- |
| Two of four validators at genesis | No blocks finalized |
| Three of four validators online | All finalized height 19 |
| Four validators across session boundaries | All finalized height 125 with the same hash |
| One validator offline | The remaining three advanced to height 145 |
| Two validators offline | Finality stopped at height 145 |
| Quorum restored by restarting a validator | Finality advanced to height 164 |
| Last validator restarted | All four reached height 213 |
| Fresh full node | Synced to height 217 and followed new blocks |
| Fresh warp node | Completed warp proof sync, then state sync, and reached height 287 |
| All six nodes following new blocks | All finalized height 297 with the same hash |

The common finalized hash at height 297 was:

```text
0x6af7c68264c67a29eca87dbf20cd95325898fb310ae5e4dcb8155b56f8ef8f33
```

The warp test used `--sync warp --state-pruning 256`. Its log explicitly recorded `Warp sync is complete, continuing with state sync` and `State sync is complete, continuing with block sync`, followed by live block finalization. It did not merely start a node with a warp flag.

The live session test used a fixed validator set. Session registration and PoP checks were exercised in library tests; live validator-set replacement was not part of this network run. The test covers a new solochain, not migration of an existing Aura/GRANDPA database or a Cumulus parachain.

## Reproduce and inspect

Follow the [README quickstart](../README.md) and run `python3 scripts/test_network.py`. The script starts and stops its own processes, checks RPC state, and records assertions in [network-results.json](../artifacts/network-results.json). It refuses to overwrite existing test databases.

Machine-readable results are in [validation.json](../artifacts/validation.json). Compact evidence is retained in [unit-test-results.txt](../artifacts/unit-test-results.txt) and [warp-excerpt.txt](../artifacts/warp-excerpt.txt). Full logs are local build artifacts and are excluded from Git.

After validation, `scripts/clean.sh` removes compiled output, downloaded dependencies, and test databases. Sources, lockfile, and these reports remain. Rebuilding after cleanup downloads dependencies again.
