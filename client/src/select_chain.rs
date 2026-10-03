use std::fmt::Debug;

use sp_consensus::{Error, SelectChain};
use sp_runtime::traits::{Block as BlockT, Header};
use tokio::sync::{mpsc, oneshot};

const LOG_TARGET: &str = "sc-consensus-hotstuff::select-chain";

pub type SelectChainSender<B> = mpsc::UnboundedSender<oneshot::Sender<<B as BlockT>::Header>>;
pub type SelectChainReceiver<B> = mpsc::UnboundedReceiver<oneshot::Sender<<B as BlockT>::Header>>;

pub struct HotstuffSelectChainProvider<B: BlockT> {
    sc: HotstuffSelectChain<B>,
    rx: SelectChainReceiver<B>,
}

impl<B: BlockT> Default for HotstuffSelectChainProvider<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: BlockT> HotstuffSelectChainProvider<B> {
    pub fn new() -> Self {
        let (sc, rx) = HotstuffSelectChain::new();

        Self { sc, rx }
    }

    pub fn best_block_user_requests(self) -> SelectChainReceiver<B> {
        self.rx
    }

    pub fn select_chain(&self) -> impl SelectChain<B> {
        self.sc.clone()
    }
}

#[derive(Clone, Debug)]
pub struct HotstuffSelectChain<B: BlockT> {
    best_block_request: SelectChainSender<B>,
}

impl<B: BlockT> HotstuffSelectChain<B> {
    pub fn new() -> (Self, SelectChainReceiver<B>) {
        let (tx, rx) = mpsc::unbounded_channel();

        (
            Self {
                best_block_request: tx,
            },
            rx,
        )
    }
}

#[async_trait::async_trait]
impl<B: BlockT> SelectChain<B> for HotstuffSelectChain<B> {
    async fn leaves(&self) -> Result<Vec<<B as BlockT>::Hash>, Error> {
        // not used
        Ok(Vec::new())
    }

    async fn best_chain(&self) -> Result<<B as BlockT>::Header, Error> {
        let (tx, rx) = oneshot::channel();

        self.best_block_request
            .send(tx)
            .map_err(|e| Error::Other(Box::new(e)))?;

        let best = rx.await.map_err(|e| Error::Other(Box::new(e)))?;

        log::info!(target: LOG_TARGET, "Best block: {:?}", best.hash());
        Ok(best)
    }
}
