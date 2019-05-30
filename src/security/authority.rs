use crate::err::Result;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use serde::Serialize;

use std::fmt;
use std::io::{Cursor, Read};

#[derive(Serialize, Debug, Clone, PartialOrd, PartialEq)]
pub struct Authority(u64);

impl Authority {
    pub fn from_buffer(buffer: &[u8]) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    #[inline]
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Authority> {
        let id_high = reader.read_u32::<BigEndian>()?;
        let id_low = reader.read_u16::<BigEndian>()?;

        Ok(Authority(u64::from((id_high as u16) ^ (id_low))))
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Debug, Clone, PartialOrd, PartialEq)]
pub struct SubAuthorityList(Vec<SubAuthority>);

impl SubAuthorityList {
    pub fn from_buffer(buffer: &[u8], count: u8) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buffer), count)
    }

    #[inline]
    pub fn from_reader<R: Read>(buffer: &mut R, count: u8) -> Result<SubAuthorityList> {
        let mut list: Vec<SubAuthority> = Vec::with_capacity(count as usize);

        for _ in 0..count {
            list.push(SubAuthority::from_reader(buffer)?)
        }

        Ok(SubAuthorityList(list))
    }
}

impl fmt::Display for SubAuthorityList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for element in self.0.iter() {
            write!(f, "-{}", element).expect("Writing to a String cannot fail");
        }

        Ok(())
    }
}

#[derive(Serialize, Debug, Clone, PartialOrd, PartialEq)]
pub struct SubAuthority(u32);

impl SubAuthority {
    pub fn from_buffer(buffer: &[u8]) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    #[inline]
    pub fn from_reader<R: Read>(buffer: &mut R) -> Result<SubAuthority> {
        Ok(SubAuthority(buffer.read_u32::<LittleEndian>()?))
    }
}

impl fmt::Display for SubAuthority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::security::authority::{Authority, SubAuthority, SubAuthorityList};

    #[test]
    fn test_parse_authority() {
        let buffer: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05];

        let authority = Authority::from_buffer(&buffer).unwrap();
        assert_eq!(authority.0, 5);
    }

    #[test]
    fn test_parse_sub_authority() {
        let buffer: &[u8] = &[0x12, 0x00, 0x00, 0x00];

        let sub_authority = SubAuthority::from_buffer(&buffer).unwrap();
        assert_eq!(sub_authority.0, 18);
    }

    #[test]
    fn test_parses_sub_authority_list() {
        let buffer: &[u8] = &[
            0x12, 0x00, 0x00, 0x00, 0x00, 0x13, 0x18, 0x00, 0x3F, 0x00, 0x0F, 0x00,
        ];

        let sub_authority = SubAuthorityList::from_buffer(&buffer, 3).unwrap();

        assert_eq!(sub_authority.0[0].0, 18);
        assert_eq!(sub_authority.0[1].0, 1_577_728);
        assert_eq!(sub_authority.0[2].0, 983_103);
    }
}
