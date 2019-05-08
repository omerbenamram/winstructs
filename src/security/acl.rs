//! ACL
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-list-acl

use crate::security::ace::Ace;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::error::Error;
use std::io::Read;

#[derive(Serialize, Debug, Clone)]
pub struct Acl {
    pub revision: u8,
    #[serde(skip_serializing)]
    pub padding1: u8,
    #[serde(skip_serializing)]
    pub size: u16,
    pub count: u16,
    #[serde(skip_serializing)]
    pub padding2: u16,
    pub entries: Vec<Ace>,
}

impl Acl {
    pub fn new<R: Read>(reader: &mut R) -> Result<Acl, Box<dyn Error>> {
        let revision = reader.read_u8()?;
        let padding1 = reader.read_u8()?;
        let size = reader.read_u16::<LittleEndian>()?;
        let count = reader.read_u16::<LittleEndian>()?;
        let padding2 = reader.read_u16::<LittleEndian>()?;
        let mut entries: Vec<Ace> = Vec::new();

        for _i in 0..count {
            let ace = Ace::new(reader)?;
            entries.push(ace);
        }

        Ok(Acl {
            revision,
            padding1,
            size,
            count,
            padding2,
            entries,
        })
    }
}
