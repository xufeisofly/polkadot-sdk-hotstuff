use crate::error::ChainStatusError;
use futures::{stream::FusedStream, StreamExt};

use sc_client_api::{FinalityNotifications, ImportNotifications};
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainStatusNotification<B: BlockT> {
    /// A block has been imported.
    BlockImported((B::Hash, NumberFor<B>)),
    /// A block has been finalized.
    BlockFinalized((B::Hash, NumberFor<B>)),
}

#[async_trait::async_trait]
pub trait ChainStatusNotifier<B: BlockT>: Send + Sync {
    /// Returns a chain status notification when it is available.
    /// This method's implementation must be cancellation safe.
    async fn next(&mut self) -> Result<ChainStatusNotification<B>, ChainStatusError>;
}

pub trait BlockchainEvents<B: BlockT>: Send + Sync {
    type ChainStatusNotifier: ChainStatusNotifier<B>;

    /// Returns a chain status notifier, which will contain all the events
    /// that appeared after this call.
    fn chain_status_notifier(&self) -> Self::ChainStatusNotifier;
}

pub struct HotstuffChainStatusNotifier<B: BlockT> {
    import_notifications: ImportNotifications<B>,
    finality_notifications: FinalityNotifications<B>,
}

impl<B: BlockT> HotstuffChainStatusNotifier<B> {
    pub fn new(
        import_notifications: ImportNotifications<B>,
        finality_notifications: FinalityNotifications<B>,
    ) -> Self {
        Self {
            import_notifications,
            finality_notifications,
        }
    }
}

#[async_trait::async_trait]
impl<B: BlockT> ChainStatusNotifier<B> for HotstuffChainStatusNotifier<B> {
    async fn next(&mut self) -> Result<ChainStatusNotification<B>, ChainStatusError> {
        match (
            self.finality_notifications.is_terminated(),
            self.import_notifications.is_terminated(),
        ) {
            (true, true) => return Err(ChainStatusError::AllStreamsTerminated),
            (true, _) => return Err(ChainStatusError::JustificationStreamClosed),
            (_, true) => return Err(ChainStatusError::ImportStreamClosed),
            _ => {}
        }

        futures::select! {
            maybe_block = self.finality_notifications.next() => {
                maybe_block
                    .map(|block| ChainStatusNotification::BlockFinalized((block.hash, *block.header.number())))
                    .ok_or(ChainStatusError::JustificationStreamClosed)
            },
            maybe_block = self.import_notifications.next() => {
                maybe_block
                .map(|block| ChainStatusNotification::BlockImported((block.hash, *block.header.number())))
                .ok_or(ChainStatusError::ImportStreamClosed)
            }
            complete => Err(ChainStatusError::AllStreamsTerminated)
        }
    }
}

impl<B, C> BlockchainEvents<B> for C
where
    B: BlockT,
    C: sc_client_api::BlockchainEvents<B> + Send + Sync,
{
    type ChainStatusNotifier = HotstuffChainStatusNotifier<B>;

    fn chain_status_notifier(&self) -> HotstuffChainStatusNotifier<B> {
        HotstuffChainStatusNotifier::new(
            // NOTE: import_notification_stream will not work for initial block syncing,
            // every_import_notification_stream can be used if major syncing blocks also need to be listened, for example:
            // when a validator breaks and then rejoins the network, it may need to sync a large number of blocks
            self.import_notification_stream(),
            self.finality_notification_stream(),
        )
    }
}
