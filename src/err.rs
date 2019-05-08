use snafu::Snafu;
use std::{io, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("An I/O error has occurred: {}", "source"))]
    IoError {
        source: std::io::Error,
    },
    #[snafu(display("Unknown AceType: {}", ace_type))]
    UnknownAceType {
        ace_type: u8,
    },
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError { source: err }
    }
}
