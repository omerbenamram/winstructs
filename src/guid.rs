use byteorder::{LittleEndian, ReadBytesExt};
use serde::ser;
use std::fmt;
use std::fmt::{Debug, Display};
use std::io::Error;
use std::io::Read;

#[derive(Clone)]
pub struct Guid(pub [u8; 16]);
impl Guid {
    pub fn new<R: Read>(mut reader: R) -> Result<Guid, Error> {
        let mut buffer = [0; 16];
        reader.read_exact(&mut buffer)?;
        Ok(Guid(buffer))
    }

    pub fn to_string(&self) -> String {
        let mut slice: &[u8] = &self.0;
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            slice.read_u32::<LittleEndian>().unwrap(),
            slice.read_u16::<LittleEndian>().unwrap(),
            slice.read_u16::<LittleEndian>().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap(),
            slice.read_u8().unwrap()
        )
    }
}
impl Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl ser::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{}", self.to_string()))
    }
}
