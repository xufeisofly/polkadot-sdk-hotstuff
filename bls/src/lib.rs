#[cfg(not(feature = "std"))]
compile_error!("This crate requires the `std` feature to be enabled.");

#[cfg(all(feature = "pairing", feature = "blst"))]
compile_error!("only pairing or blst can be enabled");

mod error;
mod key;
pub mod keystore;
pub mod pair;
mod runtime;
mod signature;

pub use self::error::Error;
pub use self::key::{aggregate_public_keys, PrivateKey, PublicKey, Serialize};
pub use self::signature::{
    aggregate, fast_verify_aggregated, hash, pop_prove, pop_verify, pop_verify_batch, verify,
    verify_aggregated, verify_one, ProofOfPossession, Signature,
};

#[cfg(test)]
#[macro_use]
extern crate base64_serde;
