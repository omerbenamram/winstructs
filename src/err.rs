//! Library error types.

use std::result;
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An I/O error has occurred")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("Unknown AceType: {}", ace_type)]
    UnknownAceType { ace_type: u8 },
}
