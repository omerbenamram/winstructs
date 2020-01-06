//! This crate contains definitions and some parsing logic for structures that are common across windows formats.
//!
//! [Documentation](https://docs.rs/winstructs)
//!
//! # API
//! Generally, structs in this crate will have either `from_reader`, if they can be read from a
//! `Read` instance, or `from_stream`, if reading them requires `Read + Seek`.
//!
//! `from_buffer` is also provided as convenience, but it generally just builds a cursor and uses
//! either `from_reader` or `from_stream` internally.
//!
#![deny(unused_must_use)]
#![deny(unsafe_code)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

use std::io::{self, Read, Seek, SeekFrom};

#[macro_use]
extern crate num_derive;

#[macro_use]
pub(crate) mod macros;
pub(crate) mod utils;

pub mod err;
pub mod guid;
pub mod ntfs;
pub mod security;
pub mod timestamp;

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
