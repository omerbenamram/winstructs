//! Utilities for reading GUIDs.
//! GUIDs identify objects such as interfaces, manager entry-point vectors (EPVs), and class objects.
use crate::err::Result;

use std::fmt::{self, Display};
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::ser;

#[derive(PartialOrd, PartialEq, Clone, Debug)]
/// https://docs.microsoft.com/en-us/previous-versions/aa373931(v%3Dvs.80)
/// # Example
///
/// ```
/// # use winstructs::guid::Guid;
/// let raw_guid: &[u8] = &[0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
///                         0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd];
///
/// let guid = Guid::from_buffer(raw_guid).unwrap();
///
/// assert_eq!(format!("{}", guid), "54849625-5478-4994-A5BA-3E3B0328C30D");
/// ```
pub struct Guid {
    /// Specifies the first 8 hexadecimal digits of the GUID.
    data1: u32,
    /// Specifies the first group of 4 hexadecimal digits.
    data2: u16,
    /// Specifies the second group of 4 hexadecimal digits.
    data3: u16,
    /// Array of 8 bytes. The first 2 bytes contain the third group of 4 hexadecimal digits.
    /// The remaining 6 bytes contain the final 12 hexadecimal digits.
    data4: [u8; 8],
}

impl Guid {
    /// Creates a new GUID directly from it's components.
    pub fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Reads a GUID from a buffer.
    pub fn from_buffer(buffer: &[u8]) -> Result<Guid> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    #[deprecated = "use `from_reader`"]
    pub fn from_stream<T: Read>(stream: &mut T) -> Result<Guid> {
        Self::from_reader(stream)
    }

    /// Reads a GUID from a `Read` instance.
    pub fn from_reader<T: Read>(stream: &mut T) -> Result<Guid> {
        let data1 = stream.read_u32::<LittleEndian>()?;
        let data2 = stream.read_u16::<LittleEndian>()?;
        let data3 = stream.read_u16::<LittleEndian>()?;

        let mut data4 = [0; 8];
        stream.read_exact(&mut data4)?;

        Ok(Guid::new(data1, data2, data3, data4))
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

/// For GUIDs, a string representation is preferable to a struct for serialization.
impl ser::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
