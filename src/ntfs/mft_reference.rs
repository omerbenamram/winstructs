use crate::err::{Result};
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use serde::Serialize;

use std::io::Read;

// Represents a MFT Reference struct
// https://msdn.microsoft.com/en-us/library/bb470211(v=vs.85).aspx
// https://jmharkness.wordpress.com/2011/01/27/mft-file-reference-number/
#[derive(Serialize, Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub struct MftReference {
    pub entry: u64,
    pub sequence: u16,
}

impl MftReference {
    pub fn new(entry: u64, sequence: u16) -> Self {
        MftReference { entry, sequence }
    }

    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self::from(reader.read_u64::<LittleEndian>()?))
    }
}

impl From<u64> for MftReference {
    fn from(mft_entry: u64) -> Self {
        let as_bytes: [u8; 8] = mft_entry.to_le_bytes();

        let mut entry_bytes = as_bytes[0..6].to_vec();
        // pad the first six bytes, so read_u64 will not fail.
        entry_bytes.extend_from_slice(&[0, 0]);

        let entry = LittleEndian::read_u64(&entry_bytes);
        let sequence = LittleEndian::read_u16(&as_bytes[6..8]);

        MftReference { entry, sequence }
    }
}

#[cfg(test)]
mod tests {
    use super::MftReference;
    use std::io::Cursor;

    #[test]
    fn test_mft_reference() {
        let raw_reference = vec![0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x91];

        let mft_reference = MftReference::from_reader(&mut Cursor::new(raw_reference)).unwrap();
        assert_eq!(mft_reference.entry, 115);
        assert_eq!(mft_reference.sequence, 37224);
    }

}
