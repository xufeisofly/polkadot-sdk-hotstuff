use sp_consensus_hotstuff::SessionIndex;
use sp_runtime::traits::Block as BlockT;
use tokio::sync::mpsc::Receiver;

use crate::{
    crypto::{AggregateSignature, Crypto},
    error::{HotstuffError, HotstuffResult},
    messages::{
        high_qc_in_timeout_payload_hash, timeout_tc_payload_hash, ConsensusMessage, ConsensusOp,
        Timeout, TimeoutParams, QC, TC,
    },
    network::{HotstuffNetworkSender, Network},
    primitives::{ValidatorId, ViewNumber},
};

const LOG_TARGET: &str = "sc-consensus-hotstuff::pacemaker";

pub struct Pacemaker<B, CR, N>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    N: Network<B> + Send + 'static,
{
    network: HotstuffNetworkSender<B, N>,
    crypto: CR,
    last_timeout: Option<Timeout<B>>,
    op_rx: Receiver<ConsensusOp<B>>,
}

impl<B, CR, N> Pacemaker<B, CR, N>
where
    B: BlockT,
    CR: Crypto<B = B, S = AggregateSignature, H = B::Hash> + 'static,
    N: Network<B> + Send + 'static,
{
    pub fn new(
        network: HotstuffNetworkSender<B, N>,
        crypto: CR,
        op_rx: Receiver<ConsensusOp<B>>,
    ) -> Self {
        Self {
            network,
            crypto,
            last_timeout: None,
            op_rx,
        }
    }

    /// Broadcast timeout to all validators, including local delivery.
    pub async fn timeout(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        local_id: ValidatorId,
        high_qc: QC<B>,
        high_tc_opt: Option<TC<B>>,
    ) {
        match self
            .generate_timeout(view, session_index, local_id, high_qc, high_tc_opt)
            .await
        {
            Ok(timeout) => {
                log::trace!(target: LOG_TARGET, "Generated timeout for view {}-{}", session_index, view,);
                self.last_timeout = Some(timeout.clone());

                self.network
                    .broadcast_message(ConsensusMessage::Timeout(timeout));
            }
            Err(e) => {
                log::error!(target: LOG_TARGET, "Failed to generate timeout for view {}: {}", view, e);
            }
        }
    }

    async fn generate_timeout(
        &mut self,
        view: ViewNumber,
        session_index: SessionIndex,
        local_id: ValidatorId,
        high_qc: QC<B>,
        high_tc_opt: Option<TC<B>>,
    ) -> HotstuffResult<Timeout<B>> {
        if let Some(ref last_timeout) = self.last_timeout {
            if last_timeout.view == view && last_timeout.session_index == session_index {
                log::trace!(
                    target: LOG_TARGET,
                    "Reusing existing timeout for view {}-{}, author: {}",
                    session_index,
                    view,
                    local_id,
                );
                return Ok(last_timeout.clone());
            }
        }

        log::trace!(
            target: LOG_TARGET,
            "Generating new timeout for view {}-{}, author: {}",
            session_index,
            view,
            local_id,
        );

        let mut timeout = Timeout::<B>::new(local_id, view, session_index, Some(high_qc.clone()));
        let view_hash = timeout_tc_payload_hash::<B>(session_index, view);
        let view_sig = self.crypto.sign(&view_hash).await.map_err(|e| {
            HotstuffError::TimeoutBuild(format!("view sign failed: {view}, err: {e:?}"))
        })?;
        timeout.set_view_sig(view_sig);
        let high_qc_msg = high_qc_in_timeout_payload_hash::<B>(session_index, view, high_qc.hash());
        let high_qc_sig = self.crypto.sign(&high_qc_msg).await.map_err(|e| {
            HotstuffError::TimeoutBuild(format!(
                "high qc sign failed: {}-{}, err: {:?}",
                high_qc.session_index, high_qc.view, e
            ))
        })?;
        timeout.set_local_high_qc_sig(high_qc_sig);

        // Include the high TC to synchronize restarted validators.
        if let Some(high_tc) = high_tc_opt {
            let high_tc_sig = self.crypto.sign(&high_tc.hash()).await.map_err(|e| {
                HotstuffError::TimeoutBuild(format!(
                    "high tc sign failed: {}-{}, err: {:?}",
                    high_tc.session_index, high_tc.view, e
                ))
            })?;
            timeout.set_local_high_tc(Some(high_tc));
            timeout.set_local_high_tc_sig(high_tc_sig);
        }
        Ok(timeout)
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(message) = self.op_rx.recv() => match message {
                    ConsensusOp::<B>::Timeout(TimeoutParams{view, session_index, local_id, high_qc, high_tc_opt}) => {
                        self.timeout(
                            view,
                            session_index,
                            local_id,
                            high_qc,
                                        high_tc_opt,
                        ).await;
                    },
                    _ => { /* ignore other messages */},
                },
            }
        }
    }
}
