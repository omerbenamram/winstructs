use crate::err::{self, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use serde::Serialize;

use std::fmt;

#[derive(Serialize, Debug, Clone)]
pub struct Authority(u64);

impl Authority {
    pub fn new(buffer: &[u8]) -> Result<Authority> {
        let value = BigEndian::read_u64(&[&[0x00, 0x00], &buffer[0..6]].concat());

        Ok(Authority(value))
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct SubAuthorityList(Vec<SubAuthority>);
impl SubAuthorityList {
    pub fn new(buffer: &[u8], count: u8) -> Result<SubAuthorityList> {
        let mut list: Vec<SubAuthority> = Vec::new();

        for i in 0..count {
            //SubAuthority offset
            let o: usize = (i * 4) as usize;
            let sub = SubAuthority::new(&buffer[o..o + 4])?;
            list.push(sub);
        }

        Ok(SubAuthorityList(list))
    }

    pub fn to_string(&self) -> String {
        let mut s_vec: Vec<String> = Vec::new();
        for sa in &self.0 {
            s_vec.push(sa.to_string())
        }
        s_vec.join("-").to_string()
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct SubAuthority(u32);

impl SubAuthority {
    pub fn new(buffer: &[u8]) -> Result<SubAuthority> {
        Ok(SubAuthority(LittleEndian::read_u32(&buffer[0..4])))
    }

    pub fn to_string(&self) -> String {
        format!("{}", self.0)
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

        let authority = Authority::new(&buffer).unwrap();
        assert_eq!(authority.0, 5);
    }

    #[test]
    fn test_parse_sub_authority() {
        let buffer: &[u8] = &[0x12, 0x00, 0x00, 0x00];

        let sub_authority = SubAuthority::new(&buffer).unwrap();
        assert_eq!(sub_authority.0, 18);
    }

    #[test]
    fn test_parses_sub_authority_list() {
        let buffer: &[u8] = &[
            0x12, 0x00, 0x00, 0x00, 0x00, 0x13, 0x18, 0x00, 0x3F, 0x00, 0x0F, 0x00,
        ];

        let sub_authority = SubAuthorityList::new(&buffer, 3).unwrap();

        assert_eq!(sub_authority.0[0].0, 18);
        assert_eq!(sub_authority.0[1].0, 1_577_728);
        assert_eq!(sub_authority.0[2].0, 983_103);
    }

}
