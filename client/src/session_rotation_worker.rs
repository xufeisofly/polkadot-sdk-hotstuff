use sp_consensus_hotstuff::SessionIndex;
use sp_runtime::traits::{Block as BlockT, NumberFor, Zero};
use tokio::sync::{mpsc, oneshot};

use crate::session_info_provider::{SessionAuthorityProvider, SessionInfoService};

const LOG_TARGET: &str = "sc-consensus-hotstuff::session-rotation-worker";

pub type SessionChangedSender<B> = mpsc::Sender<SessionChanged<B>>;
pub type SessionChangedReceiver<B> = mpsc::Receiver<SessionChanged<B>>;

pub(crate) enum ServiceToWorkerMsg<B: BlockT> {
    TryAdvanceSession(NumberFor<B>, oneshot::Sender<Option<SessionChanged<B>>>),
}

#[derive(Clone, Debug)]
pub struct SessionRotationService<B: BlockT> {
    to_worker: mpsc::Sender<ServiceToWorkerMsg<B>>,
}

impl<B: BlockT> SessionRotationService<B> {
    pub async fn try_advance_session(
        &self,
        block_number: NumberFor<B>,
    ) -> Option<SessionChanged<B>> {
        let (tx, rx) = oneshot::channel();
        self.to_worker
            .send(ServiceToWorkerMsg::TryAdvanceSession(block_number, tx))
            .await
            .ok();

        rx.await.unwrap_or(None)
    }
}

#[derive(Clone, Debug)]
pub struct SessionChanged<B: BlockT> {
    pub from_session: SessionIndex,
    pub to_session: SessionIndex,
    pub block_number: NumberFor<B>,
}

pub struct SessionRotationWorker<B: BlockT> {
    session_info_service: std::sync::Arc<SessionInfoService<B>>,
    from_service: mpsc::Receiver<ServiceToWorkerMsg<B>>,
    session_changed_tx: SessionChangedSender<B>,
}

impl<B: BlockT> SessionRotationWorker<B> {
    pub fn new_with_service(
        session_info_service: std::sync::Arc<SessionInfoService<B>>,
        session_changed_tx: SessionChangedSender<B>,
    ) -> (Self, SessionRotationService<B>) {
        let (to_worker, from_service) = mpsc::channel(1);

        let worker = Self {
            session_info_service,
            from_service,
            session_changed_tx,
        };
        let service = SessionRotationService { to_worker };
        (worker, service)
    }

    async fn try_advance_session(&self, block_number: NumberFor<B>) -> Option<SessionChanged<B>> {
        if block_number.is_zero() {
            return None;
        }

        let should_end = self
            .session_info_service
            .should_end_session(block_number)
            .await;
        if !should_end {
            return None;
        }

        let from_session = self.session_info_service.current_session_index().await;
        let session_at_block = self
            .session_info_service
            .session_index_by_number(block_number)
            .await;

        let is_historical = session_at_block < from_session;
        if is_historical {
            return None;
        }

        log::info!(
            target: LOG_TARGET,
            "Start advancing current session for block #{}: session {} -> {}",
            block_number,
            from_session,
            from_session + 1
        );

        let to_session = self.session_info_service.advance_current_session().await;
        if to_session <= from_session {
            return None;
        }

        log::info!(
            target: LOG_TARGET,
            "⏭️ Successfully advance session {} -> {}",
            from_session,
            to_session,
        );

        Some(SessionChanged {
            from_session,
            to_session,
            block_number,
        })
    }

    async fn handle_try_advance_session(
        &self,
        block_number: NumberFor<B>,
        sender: oneshot::Sender<Option<SessionChanged<B>>>,
    ) {
        let changed = self.try_advance_session(block_number).await;

        if let Some(ref changed_item) = changed {
            if let Err(e) = self.session_changed_tx.send(changed_item.clone()).await {
                log::trace!(
                    target: LOG_TARGET,
                    "No session changed subscribers for session {} -> {}: {}",
                    changed_item.from_session,
                    changed_item.to_session,
                    e
                );
            }
        }

        let _ = sender.send(changed);
    }

    pub async fn run(mut self) {
        log::info!(target: LOG_TARGET, "SessionRotationWorker started");

        while let Some(msg) = self.from_service.recv().await {
            match msg {
                ServiceToWorkerMsg::TryAdvanceSession(block_number, sender) => {
                    self.handle_try_advance_session(block_number, sender).await;
                }
            }
        }

        log::info!(target: LOG_TARGET, "SessionRotationWorker exited");
    }
}
