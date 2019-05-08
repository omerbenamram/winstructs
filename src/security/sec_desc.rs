use crate::security::acl::Acl;
use crate::security::sid::Sid;
use crate::ReadSeek;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use log::debug;
use serde::{ser, Serialize};
use std::error::Error;
use std::fmt;
use std::io::{Cursor, SeekFrom};

#[derive(Serialize, Debug, Clone)]
pub struct SecurityDescriptor {
    #[serde(skip_serializing)]
    pub header: SecDescHeader,
    pub owner_sid: Sid,
    pub group_sid: Sid,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<SecurityDescriptor, Box<dyn Error>> {
        let start_offset = stream.tell()?;

        let mut header_buf = [0; 20];
        stream.read_exact(&mut header_buf)?;

        let header = SecDescHeader::from_buffer(&header_buf)?;

        stream.seek(SeekFrom::Start(
            start_offset + u64::from(header.owner_sid_offset),
        ))?;

        let owner_sid = Sid::new(stream)?;

        stream.seek(SeekFrom::Start(
            start_offset + u64::from(header.group_sid_offset),
        ))?;

        let group_sid = Sid::new(stream)?;

        let dacl = if header.dacl_offset > 0 {
            stream.seek(SeekFrom::Start(
                start_offset + u64::from(header.dacl_offset),
            ))?;
            Some(Acl::new(stream)?)
        } else {
            None
        };

        let sacl = if header.sacl_offset > 0 {
            debug!(
                "sacl at offset: {}",
                start_offset + u64::from(header.sacl_offset)
            );
            stream.seek(SeekFrom::Start(
                start_offset + u64::from(header.sacl_offset),
            ))?;
            Some(Acl::new(stream)?)
        } else {
            None
        };

        Ok(SecurityDescriptor {
            header,
            owner_sid,
            group_sid,
            dacl,
            sacl,
        })
    }
}

// Security Descriptor Header
// https://github.com/libyal/libfwnt/wiki/Security-Descriptor
bitflags! {
    pub struct SdControlFlags: u16 {
        const SE_OWNER_DEFAULTED             = 0x0001;
        const SE_GROUP_DEFAULTED             = 0x0002;
        const SE_DACL_PRESENT                = 0x0004;
        const SE_DACL_DEFAULTED              = 0x0008;
        const SE_SACL_PRESENT                = 0x0010;
        const SE_SACL_DEFAULTED              = 0x0020;
        const SE_DACL_AUTO_INHERIT_REQ       = 0x0100;
        const SE_SACL_AUTO_INHERIT_REQ       = 0x0200;
        const SE_DACL_AUTO_INHERITED         = 0x0400;
        const SE_SACL_AUTO_INHERITED         = 0x0800;
        const SE_SACL_PROTECTED              = 0x2000;
        const SE_RM_CONTROL_VALID            = 0x4000;
        const SE_SELF_RELATIVE               = 0x8000;
    }
}

impl fmt::Display for SdControlFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

impl ser::Serialize for SdControlFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct SecDescHeader {
    pub revision_number: u8,
    #[serde(skip_serializing)]
    pub padding1: u8,
    pub control_flags: SdControlFlags,
    #[serde(skip_serializing)]
    pub owner_sid_offset: u32,
    #[serde(skip_serializing)]
    pub group_sid_offset: u32,
    #[serde(skip_serializing)]
    pub sacl_offset: u32,
    #[serde(skip_serializing)]
    pub dacl_offset: u32,
}

impl SecDescHeader {
    pub fn from_buffer(buffer: &[u8]) -> Result<SecDescHeader, Box<dyn Error>> {
        let mut cursor = Cursor::new(buffer);

        let revision_number = cursor.read_u8()?;
        let padding1 = cursor.read_u8()?;
        let control_flags_bytes = cursor.read_u16::<LittleEndian>()?;
        let control_flags = SdControlFlags::from_bits_truncate(control_flags_bytes);
        let owner_sid_offset = cursor.read_u32::<LittleEndian>()?;
        let group_sid_offset = cursor.read_u32::<LittleEndian>()?;

        // Does sacl offset or dacl offset come first??
        // logicly and Zimmerman's 010 Template show dacl come first
        // but libyal and msdn documentation show dacl comes first
        // https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-descriptor-header
        let sacl_offset = cursor.read_u32::<LittleEndian>()?;
        let dacl_offset = cursor.read_u32::<LittleEndian>()?;

        Ok(SecDescHeader {
            revision_number,
            padding1,
            control_flags,
            owner_sid_offset,
            group_sid_offset,
            sacl_offset,
            dacl_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::security::sec_desc::SecDescHeader;

    #[test]
    fn test_parses_sec_desc_header() {
        let buffer: &[u8] = &[
            0x01, 0x00, 0x04, 0x98, 0x98, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00,
        ];

        let header = SecDescHeader::from_buffer(&buffer).unwrap();

        assert_eq!(header.revision_number, 1);
        assert_eq!(header.padding1, 0);
        //assert_eq!(header.control_flags.bits(),38916);
        assert_eq!(header.owner_sid_offset, 152);
        assert_eq!(header.group_sid_offset, 164);
        assert_eq!(header.sacl_offset, 0);
        assert_eq!(header.dacl_offset, 20);
    }
}
