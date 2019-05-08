use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use serde::Serialize;
use std::fmt;
use std::fmt::{Debug, Display};
use std::mem::transmute;

// Option to display references as nested
pub static mut NESTED_REFERENCE: bool = false;

#[derive(Serialize, Debug)]
pub struct MftEnumReference {
    reference: u64,
    entry: u64,
    sequence: u16,
}

// Represents a MFT Reference struct
// https://msdn.microsoft.com/en-us/library/bb470211(v=vs.85).aspx
// https://jmharkness.wordpress.com/2011/01/27/mft-file-reference-number/
#[derive(Serialize, Hash, Eq, PartialEq, Copy, Clone)]
pub struct MftReference(pub u64);

impl MftReference {
    pub fn from_entry_and_seq(&mut self, entry: u64, sequence: u16) {
        let entry_buffer: [u8; 8] = unsafe { transmute(entry.to_le()) };
        let seq_buffer: [u8; 2] = unsafe { transmute(sequence.to_le()) };
        let mut ref_buffer = vec![];
        ref_buffer.extend_from_slice(&entry_buffer[0..6]);
        ref_buffer.extend_from_slice(&seq_buffer);

        self.0 = LittleEndian::read_u64(&ref_buffer[0..8]);
    }
    pub fn get_from_entry_and_seq(entry: u64, sequence: u16) -> MftReference {
        let entry_buffer: [u8; 8] = unsafe { transmute(entry.to_le()) };
        let seq_buffer: [u8; 2] = unsafe { transmute(sequence.to_le()) };
        let mut ref_buffer = vec![];
        ref_buffer.extend_from_slice(&entry_buffer[0..6]);
        ref_buffer.extend_from_slice(&seq_buffer);

        MftReference(LittleEndian::read_u64(&ref_buffer[0..8]))
    }
    pub fn get_enum_ref(&self) -> MftEnumReference {
        let mut raw_buffer = vec![];
        raw_buffer.write_u64::<LittleEndian>(self.0).unwrap();
        MftEnumReference {
            reference: LittleEndian::read_u64(&raw_buffer[0..8]),
            entry: LittleEndian::read_u64(&[&raw_buffer[0..6], &[0, 0]].concat()),
            sequence: LittleEndian::read_u16(&raw_buffer[6..8]),
        }
    }
    pub fn get_entry_number(&self) -> u64 {
        let mut raw_buffer = vec![];
        raw_buffer.write_u64::<LittleEndian>(self.0).unwrap();

        LittleEndian::read_u64(&[&raw_buffer[0..6], &[0, 0]].concat())
    }
}

impl Display for MftReference {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for MftReference {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]

mod tests {
    use crate::reference::MftReference;
    use byteorder::{LittleEndian, ByteOrder};

    #[test]
    fn test_mft_reference() {
        use std::mem;
        let raw_reference: &[u8] = &[0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x91];

        let mft_reference = MftReference(LittleEndian::read_u64(&raw_reference[0..8]));
        assert_eq!(mft_reference.0, 10_477_624_533_077_459_059);
        assert_eq!(format!("{}", mft_reference), "10477624533077459059");
        // assert_eq!(mft_reference.sequence,37224);

        let mft_reference_01 = MftReference::get_from_entry_and_seq(115, 37224);
        assert_eq!(mft_reference_01.0, 10_477_624_533_077_459_059);

        let mut mft_reference_02: MftReference = unsafe { mem::zeroed() };
        assert_eq!(mft_reference_02.0, 0);
        mft_reference_02.from_entry_and_seq(115, 37224);
        assert_eq!(mft_reference_02.0, 10_477_624_533_077_459_059);
    }

}
