use sc_client_api::{
    AuxStore, Backend, BlockBackend, ExecutorProvider, Finalizer, LockImportRun, StorageProvider,
};
use sc_consensus::BlockImport;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata};
use sp_runtime::traits::Block as BlockT;

use crate::chain_status::BlockchainEvents;

/// A trait that includes all the client functionalities hotstuff requires.
/// Ideally this would be a trait alias, we're not there yet.
/// tracking issue <https://github.com/rust-lang/rust/issues/41517>
pub trait HotstuffClient<Block, BE>:
    LockImportRun<Block, BE>
    + Finalizer<Block, BE>
    + AuxStore
    + HeaderMetadata<Block, Error = ClientError>
    + HeaderBackend<Block>
    + BlockchainEvents<Block>
    + ProvideRuntimeApi<Block>
    + ExecutorProvider<Block>
    + BlockImport<Block, Error = sp_consensus::Error>
    + StorageProvider<Block, BE>
    + CallApiAt<Block>
    + BlockBackend<Block>
where
    BE: Backend<Block>,
    Block: BlockT,
{
}

impl<Block, BE, T> HotstuffClient<Block, BE> for T
where
    BE: Backend<Block>,
    Block: BlockT,
    T: LockImportRun<Block, BE>
        + Finalizer<Block, BE>
        + AuxStore
        + HeaderMetadata<Block, Error = ClientError>
        + HeaderBackend<Block>
        + BlockchainEvents<Block>
        + ProvideRuntimeApi<Block>
        + ExecutorProvider<Block>
        + BlockImport<Block, Error = sp_consensus::Error>
        + StorageProvider<Block, BE>
        + CallApiAt<Block>
        + BlockBackend<Block>,
{
}
