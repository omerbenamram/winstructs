//! ACE
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-entry-ace

use crate::guid::Guid;
use crate::security::sid::Sid;
use crate::utils;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{ser, Serialize};
use std::error::Error;
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
    pub fn new<R: Read>(reader: &mut R) -> Result<Ace, Box<dyn Error>> {
        let ace_type_byte = reader.read_u8()?;
        let ace_type = AceType::from_u8(ace_type_byte)
            .ok_or_else(|| format!("Unknown AceType: {}", ace_type_byte))?;
        let ace_flags = AceFlags::from_bits_truncate(reader.read_u8()?);
        let size = reader.read_u16::<LittleEndian>()?;

        // Create data buffer
        let mut data_buffer = vec![0; (size - 4) as usize];
        reader.read_exact(&mut data_buffer)?;

        // Get data structure
        let data = if ace_type.is_basic() {
            AceData::Basic(AceBasic::new(Cursor::new(data_buffer))?)
        } else if ace_type.is_object() {
            AceData::Object(AceObject::new(Cursor::new(data_buffer))?)
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

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    SystemAudit,
    SystemAlarm,
    AccessAllowedCompound,
    AccessAllowedObject,
    AccessDeniedObject,
    SystemAuditObject,
    SystemAlarmObject,
    AccessAllowedCallback,
    AccessDeniedCallback,
    AccessAllowedCallbackObject,
    AccessDeniedCallbackObject,
    SystemAuditCallback,
    SystemAlarmCallback,
    SystemAuditCallbackObject,
    SystemAlarmCallbackObject,
    SystemMandatoryLabel,
}

impl AceType {
    pub fn from_u8(byte: u8) -> Option<AceType> {
        match byte {
            0x00 => Some(AceType::AccessAllowed),
            0x01 => Some(AceType::AccessDenied),
            0x02 => Some(AceType::SystemAudit),
            0x03 => Some(AceType::SystemAlarm),
            0x04 => Some(AceType::AccessAllowedCompound),
            0x05 => Some(AceType::AccessAllowedObject),
            0x06 => Some(AceType::AccessDeniedObject),
            0x07 => Some(AceType::SystemAuditObject),
            0x08 => Some(AceType::SystemAlarmObject),
            0x09 => Some(AceType::AccessAllowedCallback),
            0x0a => Some(AceType::AccessDeniedCallback),
            0x0b => Some(AceType::AccessAllowedCallbackObject),
            0x0c => Some(AceType::AccessDeniedCallbackObject),
            0x0d => Some(AceType::SystemAuditCallback),
            0x0e => Some(AceType::SystemAlarmCallback),
            0x0f => Some(AceType::SystemAuditCallbackObject),
            0x10 => Some(AceType::SystemAlarmCallbackObject),
            0x11 => Some(AceType::SystemMandatoryLabel),
            _ => None,
        }
    }

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
    pub fn new<R: Read>(mut reader: R) -> Result<AceBasic, Box<dyn Error>> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let sid = Sid::new(&mut reader)?;

        Ok(AceBasic { access_rights, sid })
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct AceObject {
    pub access_rights: u32,
    pub flags: u32,
    pub object_type: Guid,
    pub inherited_type: Guid,
    pub sid: Sid,
}
impl AceObject {
    pub fn new<R: Read>(mut reader: R) -> Result<AceObject, Box<dyn Error>> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;
        let object_type = Guid::from_stream(&mut reader)?;
        let inherited_type = Guid::from_stream(&mut reader)?;
        let sid = Sid::new(&mut reader)?;

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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
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

impl fmt::Display for AceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

impl ser::Serialize for AceFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

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

impl fmt::Display for StandardAccessFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

impl ser::Serialize for StandardAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

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

impl fmt::Display for NonFolderAccessFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

impl ser::Serialize for NonFolderAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

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

impl fmt::Display for FolderAccessFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}
impl ser::Serialize for FolderAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}
