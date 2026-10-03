//! Hotstuff integration into the official solochain service.
use futures::StreamExt;
use sc_client_api::BlockBackend;
use sc_consensus_hotstuff as hotstuff;
use sc_consensus_hotstuff_bls::keystore::Keystore;
use sc_network::NetworkEventStream;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncConfig};
use sc_telemetry::{Telemetry, TelemetryWorker};
use solochain_template_runtime::{apis::RuntimeApi, opaque::Block};
use std::{sync::Arc, time::Duration};

pub(crate) type FullClient = sc_service::TFullClient<
    Block,
    RuntimeApi,
    sc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>,
>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = hotstuff::select_chain::HotstuffSelectChain<Block>;
type ImportWorker =
    hotstuff::block_importer::BlockImportWorker<Block, FullBackend, FullClient, FullSelectChain>;
type SessionWorker = hotstuff::session_info_provider::SessionInfoWorker<Block, FullClient>;
pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
    (
        ImportWorker,
        hotstuff::block_importer::BlockImportService<Block>,
        hotstuff::block_importer::SyncEventReceiver<Block>,
        SessionWorker,
        Arc<hotstuff::session_info_provider::SessionInfoService<Block>>,
        hotstuff::select_chain::SelectChainReceiver<Block>,
        Option<Telemetry>,
    ),
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;
    let executor = sc_service::new_wasm_executor::<sp_io::SubstrateHostFunctions>(&config.executor);
    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, t)| t.handle()),
            executor,
            vec![],
        )?;
    let client = Arc::new(client);
    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });
    // The example's built-in --alice/--bob/... flags provision deterministic LOCAL TEST keys only.
    if let Some(seed) = &config.dev_key_seed {
        let store = keystore_container.keystore();
        store
            .ed25519_generate_new(sp_consensus_hotstuff::HOTSTUFF_KEY_TYPE, Some(seed))
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        store
            .sr25519_generate_new(
                sp_consensus_hotstuff::HOTSTUFF_AUTH_DISC_KEY_TYPE,
                Some(seed),
            )
            .map_err(|e| ServiceError::Other(e.to_string()))?;
    }
    let (select_chain, requests) = FullSelectChain::new();
    let transaction_pool = Arc::from(
        sc_transaction_pool::Builder::new(
            task_manager.spawn_essential_handle(),
            client.clone(),
            config.role.is_authority().into(),
        )
        .with_options(config.transaction_pool.clone())
        .with_prometheus(config.prometheus_registry())
        .build(),
    );
    let (session_worker, session_service) =
        hotstuff::session_info_provider::SessionInfoWorker::new_with_service(
            client.clone(),
            keystore_container.keystore(),
        )?;
    let session_service = Arc::new(session_service);
    let (worker, import, events) = hotstuff::block_import(
        client.clone(),
        select_chain.clone(),
        session_service.clone(),
        hotstuff::metrics::MetricsOpt::new(config.prometheus_registry()),
    )?;
    let adapter = hotstuff::block_importer::SyncBlockImportAdapter::new(import.clone());
    let import_queue = hotstuff::import_queue(
        Box::new(adapter.clone()),
        Some(Box::new(adapter)),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    )?;
    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (
            worker,
            import,
            events,
            session_worker,
            session_service,
            requests,
            telemetry,
        ),
    })
}

pub fn new_full<
    N: sc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>,
>(
    mut config: Configuration,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (worker, import, events, session_worker, session_service, requests, mut telemetry),
    } = new_partial(&config)?;
    let mut net_config = sc_network::config::FullNetworkConfiguration::<Block, _, N>::new(
        &config.network,
        config.prometheus_registry().cloned(),
    );
    let metrics = N::register_notification_metrics(config.prometheus_registry());
    let protocol = hotstuff::protocol_standard_name(
        &client.block_hash(0)?.expect("genesis exists"),
        &config.chain_spec,
    );
    let (protocol_config, notifications) = hotstuff::hotstuff_peers_set_config::<_, N>(
        protocol.clone(),
        metrics.clone(),
        net_config.peer_store_handle(),
    );
    net_config.add_notification_protocol(protocol_config);
    let warp = hotstuff::warp_proof::NetworkProvider::new(backend.clone(), client.clone());
    let (network, system_rpc_tx, tx_handler_controller, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            spawn_essential_handle: task_manager.spawn_essential_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_config: Some(WarpSyncConfig::WithProvider(Arc::new(warp))),
            block_relay: None,
            metrics,
        })?;
    let role = config.role;
    let registry = config.prometheus_registry().cloned();
    let dht = network
        .event_stream("hotstuff-discovery")
        .filter_map(|e| async move {
            match e {
                sc_network::Event::Dht(event) => Some(event),
                _ => None,
            }
        })
        .boxed();
    let (discovery_worker, discovery_service) =
        sc_authority_discovery::new_worker_and_service_with_config(
            sc_authority_discovery::WorkerConfig {
                publish_non_global_ips: true,
                public_addresses: config.network.public_addresses.clone(),
                max_query_interval: Duration::from_secs(2),
                keystore_refresh_interval: Duration::from_secs(5),
                ..Default::default()
            },
            client.clone(),
            Arc::new(network.clone()),
            dht,
            if role.is_authority() {
                sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore())
            } else {
                sc_authority_discovery::Role::Discover
            },
            registry.clone(),
            task_manager.spawn_handle(),
        );
    task_manager
        .spawn_essential_handle()
        .spawn("hotstuff-discovery", None, discovery_worker.run());
    let bls_path = config
        .keystore
        .path()
        .ok_or_else(|| ServiceError::Other("Use --base-path for Hotstuff's BLS keystore".into()))?
        .join("sc-consensus-hotstuff-bls");
    let mut bls = sc_consensus_hotstuff_bls::keystore::SimpleKeystore::new(bls_path);
    if let Some(seed) = &config.dev_key_seed {
        bls.import_from_seed(&sc_consensus_hotstuff_bls::pair::Seed(
            sp_io::hashing::blake2_256(seed.as_bytes()),
        ))
        .map_err(|e| ServiceError::Other(e.to_string()))?;
    } else {
        bls.reload_pair()
            .map_err(|e| ServiceError::Other(e.to_string()))?;
    }
    if role.is_authority() && !bls.has_pair() {
        return Err(ServiceError::Other("Missing Hotstuff BLS key".into()));
    }
    let rpc_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        Box::new(move |_| {
            crate::rpc::create_full(crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
            })
            .map_err(Into::into)
        })
    };
    // Keys were provisioned above, including BLS. Avoid SDK automatic rotation.
    config.dev_key_seed = None;
    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: Arc::new(network.clone()),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder,
        backend: backend.clone(),
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: telemetry.as_mut(),
        tracing_execute_block: None,
    })?;
    hotstuff::consensus::run_hotstuff(hotstuff::consensus::HotstuffParams {
        create_inherent_data_providers: |_, ()| async move {
            Ok(sp_timestamp::InherentDataProvider::from_system_time())
        },
        network,
        sync: Arc::new(sync_service),
        keystore: keystore_container.keystore(),
        bls_keystore: Arc::new(bls),
        client,
        backend,
        pool: transaction_pool,
        notification_service: notifications,
        authority_discovery_service: discovery_service,
        select_chain,
        best_block_request_rx: requests,
        block_importer_worker: worker,
        block_importer_service: import,
        session_info_service: session_service,
        sync_event_rx: events,
        protocol_name: protocol,
        spawn_handle: task_manager.spawn_essential_handle(),
        metrics: hotstuff::metrics::MetricsOpt::new(registry.as_ref()),
        is_authority: role.is_authority(),
        session_info_worker: session_worker,
    })?;
    Ok(task_manager)
}

/// Start the same verification/finality workers for CLI check-block and import-blocks.
pub fn offline_import(
    config: &Configuration,
) -> Result<
    (
        Arc<FullClient>,
        TaskManager,
        sc_consensus::DefaultImportQueue<Block>,
    ),
    ServiceError,
> {
    let sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        other: (worker, import, events, session_worker, session_service, _, _),
        ..
    } = new_partial(config)?;
    hotstuff::consensus::run_hotstuff_import_workers(hotstuff::consensus::ImportWorkerParams {
        client: client.clone(),
        backend,
        block_importer_worker: worker,
        block_importer_service: import,
        sync_event_rx: events,
        session_info_worker: session_worker,
        session_info_service: session_service,
        spawn_handle: task_manager.spawn_essential_handle(),
    })?;
    Ok((client, task_manager, import_queue))
}
