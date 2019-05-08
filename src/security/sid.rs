//! SID
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-identifier

use crate::security::authority::{Authority, SubAuthorityList};
use byteorder::ReadBytesExt;
use serde::ser;
use std::error::Error;
use std::fmt;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct Sid {
    revision_number: u8,
    sub_authority_count: u8,
    authority: Authority,
    sub_authorities: SubAuthorityList,
}
impl Sid {
    pub fn new<R: Read>(mut reader: R) -> Result<Sid, Box<dyn Error>> {
        let revision_number = reader.read_u8()?;
        let sub_authority_count = reader.read_u8()?;

        let mut buf_a = [0; 6];
        reader.read_exact(&mut buf_a)?;
        let authority = Authority::new(&buf_a)?;

        let mut buf_sa = vec![0; (sub_authority_count * 4) as usize];
        reader.read_exact(&mut buf_sa)?;
        let sub_authorities = SubAuthorityList::new(&buf_sa.as_slice(), sub_authority_count)?;

        Ok(Sid {
            revision_number,
            sub_authority_count,
            authority,
            sub_authorities,
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "S-{}-{}-{}",
            self.revision_number,
            self.authority,
            self.sub_authorities.to_string()
        )
    }
}
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl ser::Serialize for Sid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{}", self.to_string()))
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

        let sid = Sid::new(buffer).unwrap();

        assert_eq!(format!("{}", sid), "S-1-5-18");
    }

}
