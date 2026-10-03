use prometheus_endpoint::{register, Gauge, PrometheusError, Registry, U64};

/// Metrics for Hotstuff consensus
#[derive(Clone)]
pub struct Metrics {
    pub current_view: Gauge<U64>,
    pub high_qc_view: Gauge<U64>,
    pub high_tc_view: Gauge<U64>,
    pub latest_vote_view: Gauge<U64>,
    pub proposal_construction_time_ms: Gauge<U64>,
    pub block_builder_push_avg_time_us: Gauge<U64>,
    pub qc_generation_time_ms: Gauge<U64>,
    pub tc_generation_time_ms: Gauge<U64>,
    pub txs_count: Gauge<U64>,
    pub txpool_ready: Gauge<U64>,
    pub txpool_future: Gauge<U64>,
    pub view_duration_ms: Gauge<U64>,
    pub current_session: Gauge<U64>,
    pub session_authorities_count: Gauge<U64>,
    pub session_reserved_peers_count: Gauge<U64>,
    pub peer_connected_total: Gauge<U64>,
    pub session_is_authority: Gauge<U64>,
}

impl Metrics {
    pub fn register(registry: &Registry) -> Result<Self, PrometheusError> {
        let metrics = Self {
            current_view: register(
                Gauge::new("hotstuff_current_view", "Current consensus view number")?,
                registry,
            )?,
            current_session: register(
                Gauge::new(
                    "hotstuff_current_session",
                    "Current consensus session index",
                )?,
                registry,
            )?,
            high_qc_view: register(
                Gauge::new("hotstuff_high_qc_view", "View number of the highest QC")?,
                registry,
            )?,
            high_tc_view: register(
                Gauge::new("hotstuff_high_tc_view", "View number of the highest TC")?,
                registry,
            )?,
            latest_vote_view: register(
                Gauge::new("hotstuff_latest_vote_view", "Latest sent vote view number")?,
                registry,
            )?,
            proposal_construction_time_ms: register(
                Gauge::new(
                    "hotstuff_proposal_construction_time_ms",
                    "Time spent for proposal construction",
                )?,
                registry,
            )?,
            block_builder_push_avg_time_us: register(
                Gauge::new(
                    "hotstuff_block_builder_push_avg_time_us",
                    "Average time spent per extrinsic in block_builder.push",
                )?,
                registry,
            )?,
            qc_generation_time_ms: register(
                Gauge::new(
                    "hotstuff_qc_generation_time_ms",
                    "Time spent for QC generation from first vote to quorum",
                )?,
                registry,
            )?,
            tc_generation_time_ms: register(
                Gauge::new(
                    "hotstuff_tc_generation_time_ms",
                    "Time spent for TC generation from first timeout to quorum",
                )?,
                registry,
            )?,
            txs_count: register(
                Gauge::new(
                    "hotstuff_txs_count",
                    "Number of transactions in current block",
                )?,
                registry,
            )?,
            txpool_ready: register(
                Gauge::new(
                    "hotstuff_txpool_ready",
                    "Number of ready transactions in tx pool",
                )?,
                registry,
            )?,
            txpool_future: register(
                Gauge::new(
                    "hotstuff_txpool_future",
                    "Number of future transactions in tx pool",
                )?,
                registry,
            )?,
            view_duration_ms: register(
                Gauge::new("hotstuff_view_duration_ms", "Current view timeout duration")?,
                registry,
            )?,
            session_authorities_count: register(
                Gauge::new(
                    "hotstuff_session_authorities_count",
                    "Number of authorities in current session",
                )?,
                registry,
            )?,
            session_reserved_peers_count: register(
                Gauge::new(
                    "hotstuff_session_reserved_peers_count",
                    "Number of reserved peers in current session",
                )?,
                registry,
            )?,
            peer_connected_total: register(
                Gauge::new(
                    "hotstuff_peer_connected_total",
                    "Net number of connected peer events minus disconnected peer events",
                )?,
                registry,
            )?,
            session_is_authority: register(
                Gauge::new(
                    "hotstuff_session_is_authority",
                    "Whether this node is an authority in current session (1=yes, 0=no)",
                )?,
                registry,
            )?,
        };
        metrics.peer_connected_total.set(0);
        Ok(metrics)
    }

    pub fn update_session_rotation(
        &self,
        session: u64,
        authorities_count: u64,
        reserved_peers_count: u64,
        is_authority: bool,
    ) {
        self.current_session.set(session);
        self.session_authorities_count.set(authorities_count);
        self.session_reserved_peers_count.set(reserved_peers_count);
        self.session_is_authority
            .set(if is_authority { 1 } else { 0 });
    }

    pub fn update_pcstate(
        &self,
        current_view: u64,
        high_qc_view: u64,
        high_tc_view: u64,
        txs_count: u64,
        view_duration_ms: u64,
        current_session: u64,
    ) {
        self.current_view.set(current_view);
        self.high_qc_view.set(high_qc_view);
        self.high_tc_view.set(high_tc_view);
        self.txs_count.set(txs_count);
        self.view_duration_ms.set(view_duration_ms);
        self.current_session.set(current_session);
    }
}

/// Optional metrics wrapper
#[derive(Clone)]
pub struct MetricsOpt(pub Option<Metrics>);

impl MetricsOpt {
    pub fn new(registry: Option<&Registry>) -> Self {
        Self(registry.and_then(|r| Metrics::register(r).ok()))
    }

    pub fn update_pcstate(
        &self,
        current_view: u64,
        high_qc_view: u64,
        high_tc_view: u64,
        txs_count: u64,
        view_duration_ms: u64,
        current_session: u64,
    ) {
        if let Some(ref m) = self.0 {
            m.update_pcstate(
                current_view,
                high_qc_view,
                high_tc_view,
                txs_count,
                view_duration_ms,
                current_session,
            );
        }
    }

    pub fn set_proposal_construction_time_ms(&self, time_ms: u64) {
        if let Some(ref m) = self.0 {
            m.proposal_construction_time_ms.set(time_ms);
        }
    }

    pub fn set_qc_generation_time_ms(&self, time_ms: u64) {
        if let Some(ref m) = self.0 {
            m.qc_generation_time_ms.set(time_ms);
        }
    }

    pub fn set_block_builder_push_avg_time_us(&self, time_us: u64) {
        if let Some(ref m) = self.0 {
            m.block_builder_push_avg_time_us.set(time_us);
        }
    }

    pub fn set_tc_generation_time_ms(&self, time_ms: u64) {
        if let Some(ref m) = self.0 {
            m.tc_generation_time_ms.set(time_ms);
        }
    }

    pub fn set_latest_vote_view(&self, view: u64) {
        if let Some(ref m) = self.0 {
            m.latest_vote_view.set(view);
        }
    }

    pub fn set_txpool_status(&self, ready: u64, future: u64) {
        if let Some(ref m) = self.0 {
            m.txpool_ready.set(ready);
            m.txpool_future.set(future);
        }
    }

    pub fn update_session_rotation(
        &self,
        session: u64,
        authorities_count: u64,
        reserved_peers_count: u64,
        is_authority: bool,
    ) {
        if let Some(ref m) = self.0 {
            m.update_session_rotation(
                session,
                authorities_count,
                reserved_peers_count,
                is_authority,
            );
        }
    }

    pub fn inc_peer_connected_total(&self) {
        if let Some(ref m) = self.0 {
            m.peer_connected_total.inc();
        }
    }

    pub fn dec_peer_connected_total(&self) {
        if let Some(ref m) = self.0 {
            m.peer_connected_total.dec();
        }
    }
}
