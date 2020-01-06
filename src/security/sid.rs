//! SID
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-identifier
use crate::err::Result;
use crate::security::authority::{Authority, SubAuthorityList};
use byteorder::ReadBytesExt;
use serde::ser;

use std::fmt;
use std::io::{Cursor, Read};

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub struct Sid {
    revision_number: u8,
    sub_authority_count: u8,
    authority: Authority,
    sub_authorities: SubAuthorityList,
}

impl Sid {
    pub fn from_buffer(buffer: &[u8]) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Sid> {
        let revision_number = reader.read_u8()?;
        let sub_authority_count = reader.read_u8()?;

        let authority = Authority::from_reader(reader)?;
        let sub_authorities = SubAuthorityList::from_reader(reader, sub_authority_count)?;

        Ok(Sid {
            revision_number,
            sub_authority_count,
            authority,
            sub_authorities,
        })
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "S-{}-{}{}",
            self.revision_number,
            self.authority,
            self.sub_authorities.to_string()
        )
    }
}

impl ser::Serialize for Sid {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::security::sid::Sid;

    #[test]
    fn test_parses_sid() {
        let buffer: &[u8] = &[
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];

        let sid = Sid::from_buffer(buffer).unwrap();

        assert_eq!(format!("{}", sid), "S-1-5-18");
    }
}
