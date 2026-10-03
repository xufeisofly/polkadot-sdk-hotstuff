use log::Level;
use sp_consensus_hotstuff::{AuthorityId, SessionIndex};
use thiserror::Error;

use crate::primitives::{ValidatorId, ViewNumber};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("sign failed")]
    SignFailed,

    #[error("key missing: {0}")]
    KeyMissing(AuthorityId),

    #[error("verify failed")]
    VerifyFailed,

    #[error("lack of voting power")]
    LackOfVotingPower,

    #[error("lack of public keys")]
    LackOfPublicKeys,

    #[error("invalid session: {0}")]
    InvalidSession(SessionIndex),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HotstuffError {
    #[error("sign failed: {0}")]
    SignFailed(String),

    #[error("missing block: {0}")]
    MissingBlock(String),

    #[error("no txs in mempool")]
    NoTx,

    #[error("invalid params")]
    InvalidParams,

    #[error("invalid message")]
    InvalidMessage,

    #[error("client import: {0}")]
    ClientImport(String),

    #[error("invalid qc")]
    InvalidQC,

    #[error("invalid tc, view: {0}")]
    InvalidTC(ViewNumber),

    #[error("invalid agg qc, view: {0}")]
    InvalidAggQC(ViewNumber),

    #[error("signature verification failed, view: {0}")]
    InvalidSignature(ViewNumber),

    #[error("short of block")]
    BlockShortage,

    #[error("wrong leader, expected: {0}, actual: {1}")]
    UnexpectedLeader(ValidatorId, ValidatorId),

    #[error("less than quorum, view: {0}, {1}/{2}")]
    LtQuorum(ViewNumber, usize, usize),

    #[error("block build: {0}")]
    BlockBuild(String),

    #[error("aux store: {0}")]
    AuxStore(String),

    #[error("build timeout: {0}")]
    TimeoutBuild(String),

    #[error("validator id: {0}")]
    Validator(ValidatorId),

    #[error("peer info not found id: {0}")]
    PeerInfoNotFound(ValidatorId),

    #[error("old view for {0}, receiving: {1}, current: {2}")]
    OldView(String, ViewNumber, ViewNumber),

    #[error("invalid session: {0}")]
    InvalidSession(SessionIndex),

    #[error("invalid vote rule: {0}")]
    InvalidVoteRule(String),

    #[error("invalid block number: expected {0}, got {1}")]
    InvalidBlockNumber(String, String),

    #[error("{0}")]
    Other(String),
}

impl HotstuffError {
    pub fn log_level(&self) -> Level {
        match self {
            HotstuffError::SignFailed(_) => Level::Error,
            HotstuffError::MissingBlock(_) => Level::Warn,
            HotstuffError::NoTx => Level::Info,
            HotstuffError::InvalidParams => Level::Error,
            HotstuffError::InvalidMessage => Level::Error,
            HotstuffError::ClientImport(_) => Level::Warn,
            HotstuffError::InvalidQC => Level::Error,
            HotstuffError::InvalidTC(_) => Level::Error,
            HotstuffError::InvalidAggQC(_) => Level::Error,
            HotstuffError::InvalidSignature(_) => Level::Error,
            HotstuffError::BlockShortage => Level::Warn,
            HotstuffError::UnexpectedLeader(_, _) => Level::Error,
            HotstuffError::LtQuorum(_, _, _) => Level::Trace,
            HotstuffError::BlockBuild(_) => Level::Error,
            HotstuffError::AuxStore(_) => Level::Error,
            HotstuffError::TimeoutBuild(_) => Level::Warn,
            HotstuffError::Validator(_) => Level::Error,
            HotstuffError::PeerInfoNotFound(_) => Level::Error,
            HotstuffError::OldView(_, _, _) => Level::Trace,
            HotstuffError::InvalidSession(_) => Level::Trace,
            HotstuffError::InvalidVoteRule(_) => Level::Warn,
            HotstuffError::InvalidBlockNumber(_, _) => Level::Warn,
            HotstuffError::Other(_) => Level::Trace,
        }
    }
}

pub type HotstuffResult<T> = Result<T, HotstuffError>;

#[derive(Debug, Error)]
pub enum WarpError {
    /// Decoding error.
    #[error("Failed to decode: {0}")]
    DecodeScale(#[from] codec::Error),

    /// Client backend error.
    #[error("Client error: {0}")]
    Client(#[from] sp_blockchain::Error),

    /// Invalid request data.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Invalid warp proof.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}

#[derive(Debug, Error)]
pub enum ChainStatusError {
    #[error("Finalization notification stream has ended")]
    JustificationStreamClosed,

    #[error("Import notification stream has ended")]
    ImportStreamClosed,

    #[error("All streams have ended")]
    AllStreamsTerminated,
}
