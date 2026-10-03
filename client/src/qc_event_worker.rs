use crate::{
    block_importer::{ConsensusBlockImport, SyncEvent, SyncEventReceiver},
    error::HotstuffResult,
    messages::QC,
    session_rotation_worker::SessionRotationService,
    state::{ConsensusProvider, StateService},
};
use sp_runtime::traits::Block as BlockT;

const LOG_TARGET: &str = "sc-consensus-hotstuff::qc-event-worker";

pub struct QcEventWorker<B: BlockT, BI>
where
    BI: ConsensusBlockImport<B>,
{
    block_importer: BI,
    state_service: StateService<B>,
    session_rotation_service: SessionRotationService<B>,
    sync_event_rx: SyncEventReceiver<B>,
}

impl<B, BI> QcEventWorker<B, BI>
where
    B: BlockT,
    BI: ConsensusBlockImport<B>,
{
    pub fn new(
        block_importer: BI,
        state_service: StateService<B>,
        session_rotation_service: SessionRotationService<B>,
        sync_event_rx: SyncEventReceiver<B>,
    ) -> Self {
        Self {
            block_importer,
            state_service,
            session_rotation_service,
            sync_event_rx,
        }
    }

    async fn on_qc_imported(&mut self, qc: QC<B>) -> HotstuffResult<()> {
        log::info!(
            target: LOG_TARGET,
            "🏃 SyncFinalize by qc, qc.view: {}, qc.block_hash: {}, qc.block_number: {}",
            qc.view,
            qc.block_hash,
            qc.block_number,
        );

        let _ = self.state_service.advance_view(Some(&qc), None).await;
        let _ = self
            .session_rotation_service
            .try_advance_session(qc.block_number)
            .await;
        self.block_importer.try_commit(&qc).await?;

        Ok(())
    }

    async fn on_historical_qc_imported(&mut self, qc: QC<B>) {
        log::info!(
            target: LOG_TARGET,
            "📚 Historical qc synced, qc.view: {}, qc.block_hash: {}, qc.block_number: {}",
            qc.view,
            qc.block_hash,
            qc.block_number,
        );
    }

    pub async fn run(mut self) {
        log::info!(target: LOG_TARGET, "QcEventWorker started");

        while let Some(event) = self.sync_event_rx.recv().await {
            match event {
                SyncEvent::OnQC(qc) => {
                    if let Err(e) = self.on_qc_imported(*qc).await {
                        log::log!(target: LOG_TARGET, e.log_level(), "{}", e);
                    }
                }
                SyncEvent::OnHistoricalQC(qc) => {
                    self.on_historical_qc_imported(*qc).await;
                }
            }
        }

        log::warn!(target: LOG_TARGET, "QcEventWorker stopped: sync event channel closed");
        log::info!(target: LOG_TARGET, "QcEventWorker exited");
    }
}
