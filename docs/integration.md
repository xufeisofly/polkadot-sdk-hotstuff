# Replace Aura and GRANDPA in your chain

Hotstuff supplies both block production and finality. Replace the Aura/BABE authoring task and GRANDPA finality task with the runtime and node wiring below. The complete, runnable reference is [examples/solochain](../examples/solochain), adapted from the official minimal solochain template.

## Before you start

First complete the [single-node quickstart](../README.md#3-run-your-first-chain). You should have seen finalized height increase. This tutorial then applies the same integration to a new chain based on the official solochain template.

Keep your existing business pallets, balances, transaction fees, and RPC methods. You will change three things: runtime consensus/session configuration, genesis validator keys, and node service wiring. The runtime decides who may validate; the node uses those keys to propose, vote, and finalize.

Use the included example as your working reference. If you are starting a new chain, it already contains every change below. If you are modifying your own template, work through the steps in order and build after runtime configuration and again after node wiring.

## Compatibility

- Dependencies use upstream crates corresponding to `polkadot-stable2606-2`. Exact versions are in the root `Cargo.toml` and `Cargo.lock`. Align the target chain's SDK versions and dependency sources: a Git dependency and a crates.io dependency with the same name are different Rust types.
- The example uses `AccountId32`, `u32` block numbers, `BlakeTwo256`, and ordinary FRAME extrinsics. Client, block, backend, and transaction-pool types are generic. Consensus validator identities are currently 32 bytes; other account models need a stable one-to-one mapping in the runtime APIs and author mapping.
- Sessions must use a fixed `PeriodicSessions<Period, ConstU32<0>>`, with `Period > 0`. Startup reads and validates `HotstuffApi::session_schedule()`. Changing the period during chain operation or using nonperiodic sessions requires extending historical-session lookup; changing a constant alone is insufficient.
- This is solochain consensus. It does not replace relay-chain validation or finality for Cumulus parachains.
- A new chain needs no SDK modifications. Switching an existing live chain requires a separate activation-height, storage, session-key, and finality-proof migration plan.

## Step 1: Add the four crates

Keep the entire project as a separate repository or vendor directory. Add these workspace dependencies, adjusting the paths:

```toml
sp-consensus-hotstuff = { path = "../polkadot-sdk-hotstuff/primitives", default-features = false }
pallet-hotstuff = { path = "../polkadot-sdk-hotstuff/pallet", default-features = false }
sc-consensus-hotstuff = { path = "../polkadot-sdk-hotstuff/client" }
sc-consensus-hotstuff-bls = { path = "../polkadot-sdk-hotstuff/bls" }
```

The runtime depends on the first two crates and enables their `std` features in its own `std` feature. The node depends on the client, BLS, and primitives crates with `std`. Add the SDK's `pallet-session`, `pallet-authority-discovery`, and `sp-authority-discovery` to the runtime, and `sc-authority-discovery` to the node.

## Step 2: Configure the runtime

See the [runtime configuration](../examples/solochain/runtime/src/configs/mod.rs), [runtime APIs](../examples/solochain/runtime/src/apis.rs), and [runtime composition](../examples/solochain/runtime/src/lib.rs).

1. Replace Aura with `Hotstuff: pallet_hotstuff`, add `Session: pallet_session` and `AuthorityDiscovery: pallet_authority_discovery`, and remove GRANDPA. Genesis construction must put Hotstuff before Session so BLS proofs of possession are validated before session keys are cross-checked.
2. Configure `pallet_hotstuff::Config::MaxAuthorities` and `DefaultForceProposeIntervalMs`.
3. Use `sp_consensus_hotstuff::SessionKeys` as `pallet_session::Config::Keys`. Its ownership-proof validation enforces BLS PoP. Do not substitute an unchecked `OpaqueKeys` implementation.
4. Use `pallet_hotstuff::session::HotstuffSessionManager`. Configure session handlers in order: `AuthoritySessionHandler`, `BlsSessionHandler`, and `pallet_authority_discovery::Pallet`. The example manages validator candidates through root calls and does not require staking or rewards pallets.
5. Use identical `PeriodicSessions` types for `ShouldEndSession` and `NextSessionRotation`. The example's 40-block period is for rotation tests; choose a production period accounting for discovery latency and operational requirements.
6. Set `pallet_timestamp::OnTimestampSet = ()` and choose `MinimumPeriod` for the desired block cadence.

For the supplied `AccountId32` runtime, the session configuration looks like this. `Runtime`, `RuntimeEvent`, `AccountId`, and `Balances` are your existing runtime types:

```rust
use frame_support::traits::{ConstU32, ConstU64, ConstU128};

pub type SessionPeriod = ConstU32<40>;
pub type Offset = ConstU32<0>;

impl pallet_hotstuff::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxAuthorities = ConstU32<32>;
    type DefaultForceProposeIntervalMs = ConstU64<1000>;
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = pallet_hotstuff::StashOf<Self>;
    type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, Offset>;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, Offset>;
    type SessionManager = pallet_hotstuff::session::HotstuffSessionManager<Self>;
    type SessionHandler = (
        pallet_hotstuff::session::AuthoritySessionHandler<Self>,
        pallet_hotstuff::session::BlsSessionHandler<Self>,
        pallet_authority_discovery::Pallet<Self>,
    );
    type Keys = sp_consensus_hotstuff::SessionKeys;
    type WeightInfo = pallet_session::weights::SubstrateWeight<Self>;
    type DisablingStrategy = ();
    type Currency = Balances;
    type KeyDeposit = ConstU128<0>;
}

impl pallet_authority_discovery::Config for Runtime {
    type MaxAuthorities = ConstU32<32>;
}
```

Your runtime composition must include the three pallets before you can compile these implementations. Copy their declarations from [lib.rs](../examples/solochain/runtime/src/lib.rs), preserving Hotstuff-before-Session genesis order. Remove the old Aura and GRANDPA configurations and APIs at the same time so no old consensus task or digest handler remains active.

Implement `HotstuffApi<Block, BlockNumber>`:

| Method | Example implementation |
| --- | --- |
| `authorities` | `Hotstuff::authorities().to_vec()` |
| `next_authorities` | `Hotstuff::next_authorities().to_vec()` |
| `current_session_index` | `Hotstuff::current_session_index()` |
| `should_end_session` | The same `PeriodicSessions` used by the runtime |
| `force_propose_interval_ms` | `Hotstuff::force_propose_interval_ms()` |
| `session_schedule` | `(Period::get(), 0)` |

Also implement `AuthorityDiscoveryApi` by returning `AuthorityDiscovery::authorities()`. Keep the standard Core, BlockBuilder, and transaction-validation APIs. No exchange, EVM, or rewards API is required.

## Step 3: Set up genesis validators

Each validator needs three consensus public keys:

| Field | Type | Purpose |
| --- | --- | --- |
| `auth` | ed25519, key type `hots` | Proposal and consensus-message authentication |
| `bls_pk` | BLS12-381 G1, 48 bytes | QC/TC aggregate signatures |
| `auth_disc` | sr25519, key type `audi` | Standard SDK authority discovery |

The node identifies its validator ID by matching the `hots` public key in its keystore against the runtime authority set. This does not require an account private key. Validator IDs and public keys must agree across runtime APIs.

Set `hotstuff.initialAuthorities` to `(validator_id, auth, bls_pk, bls_pop, auth_disc)` tuples, and `session.keys` to matching `(validator_id, validator_id, SessionKeys)` tuples. Every BLS key requires a valid PoP; empty bytes are invalid. Do not use `session.nonAuthorityKeys` to bypass PoP registration.

The [example chain spec](../examples/solochain/node/src/chain_spec.rs) constructs matching genesis values. `--chain local` uses Alice, Bob, Charlie, and Dave; `--chain dev` uses Alice alone. These are public test keys.

Generate a fresh BLS private-key file and public PoP:

```bash
./scripts/cargo.sh run --locked -p sc-consensus-hotstuff-bls --example keygen -- ./keys/hotstuff-bls
```

The tool refuses to overwrite existing keys. Its output contains only the public key, PoP, and SCALE-encoded `Session::set_keys` proof. Place the 32-byte seed file at the path configured for `SimpleKeystore`; the example uses `<Substrate keystore>/sc-consensus-hotstuff-bls`. The file is created with Unix permissions 0600.

Provision the ed25519 and discovery keys through standard `node key insert` or `author_insertKey`, using key types `hots` and `audi`. Register or rotate keys with `Session::set_keys(keys, proof)`, where `proof = SCALE(SessionKeysProof::V1 { bls_pop })`. Register valid keys before root calls `Hotstuff::add_queued_validator`. Changes take effect through the session queue and validator-overlap checks.

The standard SDK keystore has no host function for this BLS implementation, so the example does not support `author_rotateKeys`. Use explicit BLS generation and session registration. Do not replace this with the default `impl_opaque_keys!` generation flow.

For your first local test, copy the example's `local_spec` builder with Alice/Bob/Charlie/Dave. This avoids mixing independently generated public keys and seeds while you verify the integration. After the local network works, replace those test credentials with your own keys using the steps above.

**Checkpoint:** build the runtime with its default features and Wasm output enabled. A runtime build should complete without missing `HotstuffApi`, `SessionKeys`, or session-handler errors. If a genesis build panics about BLS PoP, check that both genesis key lists describe the same validator set and that the proof belongs to the listed BLS public key.

## Step 4: Replace the node consensus service

The complete implementation is [service.rs](../examples/solochain/node/src/service.rs). Follow this order:

1. Create the SDK client, backend, and keystore. `HotstuffSelectChain::new()` returns the select chain and request receiver.
2. Create `SessionInfoWorker::new_with_service(client, keystore)?`, then call `sc_consensus_hotstuff::block_import`.
3. Pass `SyncBlockImportAdapter` as both block importer and justification importer to `import_queue`. Remove the Aura verifier and GRANDPA importer.
4. Before `build_network`, register `protocol_standard_name` and `hotstuff_peers_set_config`. Configure `warp_proof::NetworkProvider` for warp sync. The SDK requires pruned state for a warp client, for example `--sync warp --state-pruning 256`; archive state is rejected before synchronization starts.
5. Start upstream `sc_authority_discovery`: validators use `PublishAndDiscover`, other nodes use `Discover`. Provide reachable public multiaddresses; allow nonglobal addresses only for local tests.
6. Load the BLS keystore. Pass the client, backend, pool, network, sync service, discovery service, workers, receivers, and task handle to `consensus::run_hotstuff(HotstuffParams { ... })`.
7. Supply SDK `CreateInherentDataProviders<Block, ()>` through `create_inherent_data_providers`. The example supplies timestamp; chains with additional inherents can return a provider tuple. All generated inherent extrinsics are retained.

Use the example's [service.rs](../examples/solochain/node/src/service.rs) as the starting node service, then restore your application's RPC extensions and any unrelated tasks. Its `new_partial` builds the import pipeline; `new_full` builds networking and starts Hotstuff. Do not copy only the last `run_hotstuff` call: the importer, select chain, notifications, and session workers passed to it must come from the earlier setup.

The application-specific inherent provider is deliberately an argument:

```rust
create_inherent_data_providers: |_, ()| async move {
    Ok(sp_timestamp::InherentDataProvider::from_system_time())
},
```

Keep that provider for a normal solochain. Add your other inherent providers to the returned tuple when your runtime requires them. The block builder retains every inherent; it does not assume timestamp is the only one.

If you copy the template's `--alice`/`--bob` handling, also copy its development-key setup and the `config.dev_key_seed = None` assignment before `spawn_tasks`. This prevents the SDK from trying to rotate BLS keys through an unsupported host function after the example has explicitly installed them.

All nodes run import, state, session, and finality processing. Only authorities vote and propose. Ordinary nodes synchronize finality using QC justifications. Essential worker termination must propagate to node shutdown.

`check-block` and `import-blocks` must also start the import workers; see the example's `offline_import`. The example omits `revert` because reverting only blocks would leave inconsistent consensus auxiliary state.

## How this implementation chooses its behavior

There are no consensus-selection Cargo features. Carousel uses committed-block/QC-based selection. Before the first commit, and when QC signers are unavailable, it applies the same deterministic view-seeded shuffle to the authority set so an offline first authority cannot prevent startup. Alternate single-leader and round-robin modes are removed. Messages use asynchronous notification delivery with backpressure. Empty proposals are limited by the force-propose interval. Timeout messages always broadcast to all validators and carry available high-QC/high-TC evidence; no timeout leader or liveness-save mode exists.

Standard `std`/`no_std`, benchmarking, and runtime build features are compilation support rather than consensus alternatives.

## Step 5: Build, run, and verify

Build your node after the wiring changes. In this repository, the commands are:

```bash
./scripts/cargo.sh build --locked -p solochain-template-node
./target/debug/solochain-template-node key generate-node-key --file ./.cache/dev-network-key
RUST_LOG=info ./target/debug/solochain-template-node \
  --chain dev --alice --base-path ./.cache/dev-chain \
  --node-key-file ./.cache/dev-network-key \
  --no-telemetry --no-prometheus --database paritydb
```

For your own chain, substitute your binary name and the chain-spec ID you configured. On the first run, use a fresh database: an old Aura/GRANDPA database cannot be reused as a new Hotstuff genesis.

Expected sequence:

1. The node reports `Role: AUTHORITY` and starts its RPC server.
2. Hotstuff reports `Start Hotstuff` and `Init State done`.
3. The status line's best and finalized heights start increasing. With `--chain local`, this requires at least three of its four validators.
4. `chain_getFinalizedHead` changes as new blocks finalize. Query it using the curl command in the README; fetch that header and inspect its hexadecimal `number`.

If step 2 is missing, inspect service task startup. If step 2 occurs but step 3 does not, enable `--log 'info,sc-consensus-hotstuff=trace'` and inspect authority discovery, key matching, and repeated timeout/proposal errors. Do not treat successful compilation or a healthy RPC response as a consensus test.

Stop the development node, then run the multi-node test:

```bash
python3 scripts/test_network.py
```

It uses real Wasm runtimes and separate node databases. It checks quorum loss and recovery, finality, session boundaries, restart, full sync, warp sync, and finalized-block hash agreement. Results are recorded in `artifacts/network-results.json`; unit-test output is in `artifacts/tests.log`. These files report the actual run status.

Before repeating the network test, remove or relocate this project's `artifacts/network/data`. The script refuses to overwrite existing databases and stops only processes it launched. After testing and stopping all Cargo/node processes:

```bash
./scripts/clean.sh
```

Cleanup runs `cargo clean` and removes this project's `.cache` and test databases. Source, `Cargo.lock`, reports, and logs remain. Running tests again requires downloading dependencies and rebuilding.
