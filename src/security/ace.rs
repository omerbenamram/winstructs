//! ACE
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-entry-ace
use crate::err::{Error, Result};
use crate::guid::Guid;
use crate::security::sid::Sid;
use crate::utils;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{ser, Serialize};

use num_traits::FromPrimitive;

use std::fmt;
use std::io::{Cursor, Read};

#[derive(Serialize, Debug, Clone)]
pub struct Ace {
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    #[serde(skip_serializing)]
    pub size: u16,
    pub data: AceData,
}

impl Ace {
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Ace> {
        let ace_type_byte = reader.read_u8()?;
        let ace_type = AceType::from_u8(ace_type_byte).ok_or_else(|| Error::UnknownAceType {
            ace_type: ace_type_byte,
        })?;

        let ace_flags = AceFlags::from_bits_truncate(reader.read_u8()?);
        let size = reader.read_u16::<LittleEndian>()?;

        // Create data buffer
        let mut data_buffer = vec![0; (size - 4) as usize];
        reader.read_exact(&mut data_buffer)?;

        let data = if ace_type.is_basic() {
            AceData::Basic(AceBasic::from_reader(&mut Cursor::new(data_buffer))?)
        } else if ace_type.is_object() {
            AceData::Object(AceObject::from_reader(&mut Cursor::new(data_buffer))?)
        } else {
            AceData::Unhandled(RawAce(data_buffer))
        };

        Ok(Ace {
            ace_type,
            ace_flags,
            size,
            data,
        })
    }
}

#[derive(FromPrimitive, ToPrimitive, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum AceType {
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
    AccessAllowedCompound = 0x04,
    AccessAllowedObject = 0x05,
    AccessDeniedObject = 0x06,
    SystemAuditObject = 0x07,
    SystemAlarmObject = 0x08,
    AccessAllowedCallback = 0x09,
    AccessDeniedCallback = 0x0a,
    AccessAllowedCallbackObject = 0x0b,
    AccessDeniedCallbackObject = 0x0c,
    SystemAuditCallback = 0x0d,
    SystemAlarmCallback = 0x0e,
    SystemAuditCallbackObject = 0x0f,
    SystemAlarmCallbackObject = 0x10,
    SystemMandatoryLabel = 0x11,
}

impl AceType {
    pub fn is_basic(&self) -> bool {
        match self {
            AceType::AccessAllowed
            | AceType::AccessDenied
            | AceType::SystemAudit
            | AceType::SystemAlarm
            | AceType::AccessAllowedCallback
            | AceType::AccessDeniedCallback
            | AceType::SystemAuditCallback
            | AceType::SystemAlarmCallback
            | AceType::SystemMandatoryLabel => true,
            _ => false,
        }
    }

    pub fn is_object(&self) -> bool {
        match self {
            AceType::AccessAllowedObject
            | AceType::AccessDeniedObject
            | AceType::SystemAuditObject
            | AceType::SystemAlarmObject
            | AceType::AccessAllowedCallbackObject
            | AceType::AccessDeniedCallbackObject
            | AceType::SystemAuditCallbackObject
            | AceType::SystemAlarmCallbackObject => true,
            _ => false,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum AceData {
    Basic(AceBasic),
    Object(AceObject),
    Unhandled(RawAce),
}

#[derive(Serialize, Debug, Clone)]
pub struct AceBasic {
    pub access_rights: u32,
    pub sid: Sid,
}

impl AceBasic {
    pub fn from_reader<R: Read>(mut reader: &mut R) -> Result<AceBasic> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let sid = Sid::from_reader(&mut reader)?;

        Ok(AceBasic { access_rights, sid })
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct AceObject {
    pub access_rights: u32,
    pub flags: AceObjectFlags,
    pub object_type: Option<Guid>,
    pub inherited_type: Option<Guid>,
    pub sid: Sid,
}

impl AceObject {
    pub fn from_reader<R: Read>(mut reader: &mut R) -> Result<AceObject> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let flags = AceObjectFlags::from_bits_truncate(reader.read_u32::<LittleEndian>()?);
        let mut object_type = None;
        if flags.contains(AceObjectFlags::ACE_OBJECT_TYPE_PRESENT) {
            object_type = Some(Guid::from_reader(&mut reader)?);
        }
        let mut inherited_type = None;
        if flags.contains(AceObjectFlags::ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            inherited_type = Some(Guid::from_reader(&mut reader)?);
        }
        let sid = Sid::from_reader(&mut reader)?;

        Ok(AceObject {
            access_rights,
            flags,
            object_type,
            inherited_type,
            sid,
        })
    }
}

#[derive(Clone)]
pub struct RawAce(pub Vec<u8>);

impl fmt::Debug for RawAce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", utils::to_hex_string(&self.0),)
    }
}

impl ser::Serialize for RawAce {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&utils::to_hex_string(&self.0).to_string())
    }
}

bitflags! {
    pub struct AceFlags: u8 {
        const OBJECT_INHERIT_ACE            = 0x01;
        const CONTAINER_INHERIT_ACE         = 0x02;
        const NO_PROPAGATE_INHERIT_ACE      = 0x04;
        const INHERIT_ONLY_ACE              = 0x08;
    }
}

impl_serialize_for_bitflags! {AceFlags}

bitflags! {
    pub struct StandardAccessFlags: u32 {
        // Standard access rights flags
        const SA_RIGHT_DELETE           = 0x0001_0000;
        const SA_RIGHT_READCONTROL      = 0x0002_0000;
        const SA_RIGHT_WRITESD          = 0x0004_0000;
        const SA_RIGHT_WRITEOWNER       = 0x0008_0000;
        const SA_RIGHT_SYNCHRONIZE      = 0x0010_0000;
    }
}

impl_serialize_for_bitflags! {StandardAccessFlags}

bitflags! {
    pub struct NonFolderAccessFlags: u32 {
        // Non-folder item access rights flags
        const NFA_RIGHT_READBODY                = 0x0000_0001; //FILE_READ_DATA
        const NFA_RIGHT_WRITEBODY               = 0x0000_0002; //FILE_WRITE_DATA
        const NFA_RIGHT_APPENDMSG               = 0x0000_0004;
        const NFA_RIGHT_READPROPERTY            = 0x0000_0008; //FILE_READ_EA
        const NFA_RIGHT_WRITEPROPERTY           = 0x0000_0010; //FILE_WRITE_EA
        const NFA_RIGHT_EXECUTE                 = 0x0000_0020; //FILE_EXECUTE
        const NFA_RIGHT_READATTRIBUTES          = 0x0000_0080; //FILE_READ_ATTRIBUTES
        const NFA_RIGHT_WRITEATTRIBUTES         = 0x0000_0100; //FILE_WRITE_ATTRIBUTES
        const NFA_RIGHT_WRITEOWNPROPERTY        = 0x0000_0200;
        const NFA_RIGHT_DELETEOWNITEM           = 0x0000_0400;
        const NFA_RIGHT_VIEWITEM                = 0x0000_0800;
    }
}

impl_serialize_for_bitflags! {NonFolderAccessFlags}

bitflags! {
    pub struct FolderAccessFlags: u32 {
        // Folder item access rights flags
        const FA_RIGHT_LISTCONTENTS               = 0x0000_0001; //FILE_LIST_DIRECTORY
        const FA_RIGHT_CREATEITEM                 = 0x0000_0002; //FILE_ADD_FILE
        const FA_RIGHT_CREATECONTAINER            = 0x0000_0004; //FILE_ADD_SUBDIRECTORY
        const FA_RIGHT_READPROPERTY               = 0x0000_0008; //FILE_READ_EA
        const FA_RIGHT_WRITEPROPERTY              = 0x0000_0010; //FILE_WRITE_EA
        const FA_RIGHT_READATTRIBUTES             = 0x0000_0080; //FILE_READ_ATTRIBUTES
        const FA_RIGHT_WRITEATTRIBUTES            = 0x0000_0100; //FILE_WRITE_ATTRIBUTES
        const FA_RIGHT_WRITEOWNPROPERTY           = 0x0000_0200;
        const FA_RIGHT_DELETEOWNITEM              = 0x0000_0400;
        const FA_RIGHT_VIEWITEM                   = 0x0000_0800;
        const FA_RIGHT_OWNER                      = 0x0000_4000;
        const FA_RIGHT_CONTACT                    = 0x0000_8000;
    }
}

impl_serialize_for_bitflags! {FolderAccessFlags}

bitflags! {
    pub struct AceObjectFlags: u32 {
        // Indicates whether the ObjectType and InheritedObjectType
        // fields contain valid data
        const ACE_OBJECT_TYPE_PRESENT           = 0x00000001;
        const ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002;
    }
}

impl_serialize_for_bitflags! {AceObjectFlags}

#[cfg(test)]
mod tests {
    use crate::guid::Guid;
    use crate::security::ace::{Ace, AceData, AceType};
    use crate::security::sid::Sid;
    use std::io::Cursor;

    #[test]
    fn test_parses_basic_ace() {
        let buffer: &[u8] = &[
            0x00, 0x00, 0x14, 0x00, 0xff, 0x01, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        let ace = Ace::from_reader(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(ace.ace_type, AceType::AccessAllowed);
        assert_eq!(ace.ace_flags.bits, 0);
        assert_eq!(ace.size, 20);
        assert!(ace.ace_type.is_basic());

        if let AceData::Basic(data) = ace.data {
            assert_eq!(data.access_rights, 983551);

            let buffer_sid: &[u8] = &[
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
            ];
            assert_eq!(data.sid, Sid::from_buffer(buffer_sid).unwrap());
        } else {
            panic!("ACE content does not match ACE type");
        }
    }

    #[test]
    fn test_parses_object_ace() {
        let buffer: &[u8] = &[
            0x05, 0x12, 0x38, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xd6,
            0x47, 0x5b, 0x90, 0x60, 0xb2, 0x40, 0x9f, 0x37, 0x2a, 0x4d, 0xe8, 0x8f, 0x30, 0x63,
            0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x3a, 0x31,
            0xdc, 0x2b, 0x2a, 0x09, 0x33, 0x6f, 0x41, 0x04, 0xa0, 0x51, 0x0e, 0x02, 0x00, 0x00,
        ];

        let ace = Ace::from_reader(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(ace.ace_type, AceType::AccessAllowedObject);
        assert_eq!(ace.ace_flags.bits, 2);
        assert_eq!(ace.size, 56);
        assert!(ace.ace_type.is_object());

        if let AceData::Object(data) = ace.data {
            assert_eq!(data.access_rights, 48);

            if let Some(ace_guid) = data.object_type {
                let buffer_guid: &[u8] = &[
                    0x0f, 0xd6, 0x47, 0x5b, 0x90, 0x60, 0xb2, 0x40, 0x9f, 0x37, 0x2a, 0x4d, 0xe8,
                    0x8f, 0x30, 0x63,
                ];
                assert_eq!(ace_guid, Guid::from_buffer(buffer_guid).unwrap());
            } else {
                panic!("ACE contains an object type GUID");
            }

            if let Some(_) = data.inherited_type {
                panic!("ACE does not contain object inherited type");
            }

            let buffer_sid: &[u8] = &[
                0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x3a, 0x31,
                0xdc, 0x2b, 0x2a, 0x09, 0x33, 0x6f, 0x41, 0x04, 0xa0, 0x51, 0x0e, 0x02, 0x00, 0x00,
            ];
            assert_eq!(data.sid, Sid::from_buffer(buffer_sid).unwrap());
        } else {
            panic!("ACE content does not match ACE type");
        }
    }
}
