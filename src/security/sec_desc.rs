use crate::security::acl::Acl;
use crate::security::sid::Sid;
use crate::ReadSeek;
use serde::ser;
use std::fmt;
use std::io::{self, SeekFrom};

#[derive(Debug, Clone)]
pub enum SdErrorKind {
    IoError,
    ValidationError,
}

#[derive(Debug, Clone)]
pub struct SecDescError {
    pub message: String,
    pub kind: SdErrorKind,
    pub trace: String,
}
impl From<io::Error> for SecDescError {
    fn from(err: io::Error) -> Self {
        SecDescError {
            message: format!("{}", err),
            kind: SdErrorKind::IoError,
            trace: String::new(),
        }
    }
}

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
    pub fn new<R: ReadSeek>(mut read_seek: R) -> Result<SecurityDescriptor, SecDescError> {
        let _offset = read_seek.tell();

        let mut header_buff = [0; 20];
        read_seek.read_exact(&mut header_buff)?;

        let header = SecDescHeader::new(&header_buff)?;
        read_seek.seek(SeekFrom::Start(_offset + header.owner_sid_offset as u64))?;
        let owner_sid = Sid::new(&mut read_seek)?;

        read_seek.seek(SeekFrom::Start(_offset + header.group_sid_offset as u64))?;
        let group_sid = Sid::new(&mut read_seek)?;

        let dacl = match header.dacl_offset > 0 {
            true => {
                debug!("dacl at offset: {}", _offset + header.dacl_offset as u64);
                read_seek.seek(SeekFrom::Start(_offset + header.dacl_offset as u64))?;
                Some(Acl::new(&mut read_seek)?)
            }
            false => None,
        };

        let sacl = match header.sacl_offset > 0 {
            true => {
                debug!("sacl at offset: {}", _offset + header.sacl_offset as u64);
                read_seek.seek(SeekFrom::Start(_offset + header.sacl_offset as u64))?;
                Some(Acl::new(&mut read_seek)?)
            }
            false => None,
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
    pub fn new(buffer: &[u8]) -> Result<SecDescHeader, SecDescError> {
        let revision_number = buffer[0];
        let padding1 = buffer[1];
        let control_flags =
            SdControlFlags::from_bits_truncate(LittleEndian::read_u16(&buffer[2..4]));
        let owner_sid_offset = LittleEndian::read_u32(&buffer[4..8]);
        let group_sid_offset = LittleEndian::read_u32(&buffer[8..12]);

        // Does sacl offset or dacl offset come first??
        // logicly and Zimmerman's 010 Template show dacl come first
        // but libyal and msdn documentation show dacl comes first
        // https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-descriptor-header
        let sacl_offset = LittleEndian::read_u32(&buffer[12..16]);
        let dacl_offset = LittleEndian::read_u32(&buffer[16..20]);

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
#[test]
fn sec_desc_header() {
    let buffer: &[u8] = &[
        0x01, 0x00, 0x04, 0x98, 0x98, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00,
    ];

    let header = match SecDescHeader::new(&buffer) {
        Ok(header) => header,
        Err(error) => panic!(error),
    };

    assert_eq!(header.revision_number, 1);
    assert_eq!(header.padding1, 0);
    //assert_eq!(header.control_flags.bits(),38916);
    assert_eq!(header.owner_sid_offset, 152);
    assert_eq!(header.group_sid_offset, 164);
    assert_eq!(header.sacl_offset, 0);
    assert_eq!(header.dacl_offset, 20);
}
