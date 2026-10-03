# Hotstuff for Polkadot SDK

Hotstuff consensus for Polkadot SDK blockchains, providing both block production and finality. Use the included solochain template to run a local blockchain, or integrate the consensus crates into your own chain.

**Start here:** run the included chain below. Once it works, follow [Replace Aura and GRANDPA in your chain](docs/integration.md).

## 1. Get the code

```bash
git clone https://github.com/xufeisofly/polkadot-sdk-hotstuff.git
cd polkadot-sdk-hotstuff
```

You need Rust installed through rustup, a C/C++ build toolchain, and libclang. `rust-toolchain.toml` selects Rust 1.95.0 and the Wasm target. On macOS, install Xcode command-line tools and Homebrew LLVM:

```bash
xcode-select --install
brew install llvm
```

On Ubuntu, the usual native build prerequisites are:

```bash
sudo apt-get update
sudo apt-get install build-essential clang libclang-dev pkg-config protobuf-compiler
```

The example targets official SDK release `polkadot-stable2606-2`, using published upstream crates pinned in `Cargo.lock`. The validation report identifies the platform actually tested; the package-install commands above do not imply that every platform has been tested.

## 2. Build the node

Run from the repository root:

```bash
./scripts/cargo.sh build --locked -p solochain-template-node
./target/debug/solochain-template-node --help
```

The first build downloads and compiles the SDK and the Wasm runtime. Wait for `Finished` in Cargo's output. The executable is `target/debug/solochain-template-node`.

`cargo.sh` keeps the Cargo download cache in `.cache/cargo` and build outputs in `target`. On macOS, it also configures an installed Homebrew LLVM. Use this wrapper for the commands in this guide so cleanup can reclaim the build space.

## 3. Run your first chain

First generate a networking identity (run this once; keep the file for restarts):

```bash
./target/debug/solochain-template-node key generate-node-key \
  --file ./.cache/dev-network-key
```

This prints a peer ID and saves the private networking key to the file. This key identifies the node on the P2P network; it is separate from Alice's consensus keys. Now start a single local validator with a persistent database:

```bash
RUST_LOG=info ./target/debug/solochain-template-node \
  --chain dev --alice --base-path ./.cache/dev-chain \
  --node-key-file ./.cache/dev-network-key \
  --no-telemetry --no-prometheus --database paritydb
```

Leave this terminal running. Alice is the development validator and sudo account. Her keys are public test credentials; do not use them for a public chain.

The startup log should identify `Role: AUTHORITY`, start the JSON-RPC server on port `9944`, and print `Start Hotstuff` followed by `Init State done`. After startup, the periodic node status line should show both `best: #...` and `finalized #...` increasing. A zero-peer count is normal for this single-node chain. Block hashes and exact timings vary.

For example, this is an abbreviated excerpt from a successful local run (timestamps, hashes, and peer IDs vary):

```text
Role: AUTHORITY
Running JSON-RPC server: addr=127.0.0.1:9944,[::1]:9944
Start Hotstuff, local_peer_id: ...
Init State done
HotstuffState HighQC: 17 HighTC: 13 CurView: 18 Number: 0-6 ...
Imported #6 (...)
Finalized 0x...
```

`Number: 0-6` means session 0, block 6. A finalized block is no longer just a proposal. With an empty transaction pool, you may also see `no txs in mempool, send new_view instead`; this is expected between force-propose intervals.

In a second terminal, query the finalized head twice, a few seconds apart:

```bash
curl -s http://127.0.0.1:9944 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getFinalizedHead","params":[]}'
```

Each response contains a block hash in `result`. A changing finalized hash is the useful check: an open RPC port alone does not establish that consensus works. To inspect its height, pass the returned hash to `chain_getHeader`:

```bash
curl -s http://127.0.0.1:9944 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":["REPLACE_WITH_FINALIZED_HASH"]}'
```

The header's `number` is hexadecimal. Stop the node with Ctrl-C. Running the same command again resumes its database. To start over, stop the node and run:

```bash
./target/debug/solochain-template-node purge-chain \
  --chain dev --base-path ./.cache/dev-chain --database paritydb -y
```

## 4. Try a real multi-node network

The local chain has four validators: Alice, Bob, Charlie, and Dave. Three signatures form a quorum. Three online validators can progress; two cannot finalize new blocks.

The included test manages the processes, bootnodes, keys, RPC ports, and databases for you. Stop the single-node example first, then run:

```bash
python3 scripts/test_network.py
```

The test prints a checkpoint as each assertion succeeds, starting with RPC readiness and `three of four finalizing`. It then exercises session boundaries, an offline validator, lost quorum, restart, a fresh full node, a fresh warp node, and finalized-hash agreement. A successful run ends with `all nodes follow live blocks`, exits with status 0, and writes `"success": true` to [artifacts/network-results.json](artifacts/network-results.json).

Logs are in `artifacts/network/alice.log`, `bob.log`, `charlie.log`, `dave.log`, `observer.log`, and `warp.log`. TCP ports 19940–19945 and 30940–30945 must be free. The script stops its own nodes even when a test fails. It refuses to overwrite an existing test database.

## 5. Use Hotstuff in your own chain

Follow the [integration tutorial](docs/integration.md). It walks through dependencies, runtime configuration, genesis keys, node service wiring, and verification. For a fresh project, copying `examples/solochain` and renaming your runtime/node is the shortest starting point.

| Directory | What you use it for |
| --- | --- |
| `client` | `sc-consensus-hotstuff`: node consensus, block import, networking, and finality |
| `primitives` | `sp-consensus-hotstuff`: shared `no_std` types, runtime API, session keys, and BLS PoP |
| `pallet` | `pallet-hotstuff`: validator management and session integration in your runtime |
| `bls` | `sc-consensus-hotstuff-bls`: native signing and BLS key generation |
| `examples/solochain/node` | A node service already wired to Hotstuff |
| `examples/solochain/runtime` | A runtime already wired to Hotstuff and Session |
| `scripts` | Reproducible build, network-test, and cleanup commands |

Consensus behavior is fixed: Carousel leader election, asynchronous messages, transaction-aware proposals with a force-propose interval, and timeout broadcasts to all validators. There are no alternate leader or timeout modes. Hotstuff supplies both production and finality; do not run Aura/BABE or GRANDPA alongside it for the same chain.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `libclang` cannot be found | Install libclang; on macOS use `scripts/cargo.sh` with Homebrew LLVM installed. |
| `Address already in use` | Stop the process using the RPC/P2P port or choose another port. |
| RPC works but finalized height stays at zero | Check the chain spec, validator keys, discovery addresses, and quorum. For `--chain local`, one or two validators are insufficient. |
| Waiting for authorities to be discovered | Nodes must share a chain spec and have reachable public multiaddresses and valid `audi` keys. Use the test script for local addresses. |
| Reserved-peer warning while one validator is offline | Expected when running three of four validators; check that finality still advances. |
| Warp sync rejects archive mode | Use a pruned state database, for example `--sync warp --state-pruning 256`; the test runner configures this automatically. |
| Existing test data found | Stop nodes, then remove or relocate `artifacts/network/data` before repeating the test. |
| `NetworkKeyNotFound` | Generate the networking key in step 3 and pass the same `--node-key-file` on startup. |
| Missing BLS key / `author_rotateKeys` fails | Follow the explicit key-generation and session-registration steps in the integration guide. |

For detailed consensus diagnostics, add:

```bash
--log 'info,sc-consensus-hotstuff=trace'
```

Look for `VIEW TIMEOUT`, `generate tc and agg_qc`, proposal processing, and increasing finalized height. A timeout is part of normal view recovery; repeated timeouts without progress require checking quorum and the earlier errors in the log.

## Tests and disk cleanup

```bash
./scripts/cargo.sh test --locked \
  -p sc-consensus-hotstuff -p sp-consensus-hotstuff \
  -p pallet-hotstuff -p sc-consensus-hotstuff-bls --lib
```

After all nodes and Cargo processes have stopped:

```bash
./scripts/clean.sh
```

This runs `cargo clean` and removes this project's download cache and test databases. Source, `Cargo.lock`, logs, and reports remain. A later build downloads and compiles dependencies again.

See the [validation report](docs/validation.md) for the tested platform, commands, and network results.

Source provenance and licenses are recorded in [NOTICE](NOTICE) and [artifacts/source.json](artifacts/source.json).
