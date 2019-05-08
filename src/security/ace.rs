//! ACE
//! https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-entry-ace

use crate::guid::Guid;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::ser;
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
    pub fn new<R: Read>(mut reader: R) -> Result<Ace, SecDescError> {
        let ace_type = AceType(reader.read_u8()?);
        let ace_flags = AceFlags::from_bits_truncate(reader.read_u8()?);
        let size = reader.read_u16::<LittleEndian>()?;

        // Create data buffer
        let mut data_buffer = vec![0; (size - 4) as usize];
        reader.read_exact(&mut data_buffer)?;

        // Get data structure
        let data = match ace_type.as_u8() {
            ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_DENIED_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
                AceData::Basic(AceBasic::new(Cursor::new(data_buffer))?)
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => {
                AceData::Object(AceObject::new(Cursor::new(data_buffer))?)
            }
            // Unknown data structures
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => AceData::Unhandled(RawAce(data_buffer)),
            _ => AceData::Unhandled(RawAce(data_buffer)),
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
    pub fn new<R: Read>(mut reader: R) -> Result<AceBasic, SecDescError> {
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
    pub fn new<R: Read>(mut reader: R) -> Result<AceObject, SecDescError> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;
        let object_type = Guid::new(&mut reader)?;
        let inherited_type = Guid::new(&mut reader)?;
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
        serializer.serialize_str(&format!("{}", utils::to_hex_string(&self.0)))
    }
}

pub enum AceType {
    AccessAllowedAceType = 0x00,
    AccessDeniedAceType = 0x01,
    SystemAuditAceType = 0x02,
    SystemAlarmAceType = 0x03,
    AccessAllowedCompoundAceType = 0x04,
    AccessAllowedObjectAceType = 0x05,
    AccessDeniedObjectAceType = 0x06,
    SystemAuditObjectAceType = 0x07,
    SystemAlarmObjectAceType = 0x08,
    AccessAllowedCallbackAceType = 0x09,
    AccessDeniedCallbackAceType = 0x0a,
    AccessAllowedCallbackObjectAceType = 0x0b,
    AccessDeniedCallbackObjectAceType = 0x0c,
    SystemAuditCallbackAceType = 0x0d,
    SystemAlarmCallbackAceType = 0x0e,
    SystemAuditCallbackObjectAceType = 0x0f,
    SystemAlarmCallbackObjectAceType = 0x10,
    SystemMandatoryLabelAceType = 0x11,
}

impl ToString for AceType {
    fn to_string(&self) -> String {
        match self.0 {
            0x00 => "ACCESS_ALLOWED".to_string(),
            0x01 => "ACCESS_DENIED".to_string(),
            0x03 => "SYSTEM_ALARM".to_string(),
            0x04 => "ACCESS_ALLOWED_COMPOUND".to_string(),
            0x05 => "ACCESS_ALLOWED_OBJECT".to_string(),
            0x06 => "ACCESS_DENIED_OBJECT".to_string(),
            0x07 => "SYSTEM_AUDIT_OBJECT".to_string(),
            0x08 => "ACCESS_ALLOWED_CALLBACK".to_string(),
            0x0a => "ACCESS_DENIED_CALLBACK".to_string(),
            0x0b => "ACCESS_ALLOWED_CALLBACK_OBJECT".to_string(),
            0x0c => "ACCESS_DENIED_CALLBACK_OBJECT".to_string(),
            0x0d => "SYSTEM_AUDIT_CALLBACK".to_string(),
            0x0e => "SYSTEM_ALARM_CALLBACK".to_string(),
            0x0f => "SYSTEM_AUDIT_CALLBACK_OBJECT".to_string(),
            0x10 => "SYSTEM_ALARM_CALLBACK_OBJECT".to_string(),
            0x11 => "SYSTEM_MANDATORY_LABEL".to_string(),
            _ => format!("UNKNOWN TYPE: 0x{:02X}", self.0),
        }
    }
}

impl fmt::Display for AceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl fmt::Debug for AceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl ser::Serialize for AceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
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
        const SA_RIGHT_DELETE = 0x00010000;
        const SA_RIGHT_READCONTROL = 0x00020000;
        const SA_RIGHT_WRITESD = 0x00040000;
        const SA_RIGHT_WRITEOWNER = 0x00080000;
        const SA_RIGHT_SYNCHRONIZE = 0x00100000;
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
        const NFA_RIGHT_READBODY = 0x00000001; //FILE_READ_DATA
        const NFA_RIGHT_WRITEBODY = 0x00000002; //FILE_WRITE_DATA
        const NFA_RIGHT_APPENDMSG = 0x00000004;
        const NFA_RIGHT_READPROPERTY = 0x00000008; //FILE_READ_EA
        const NFA_RIGHT_WRITEPROPERTY = 0x00000010; //FILE_WRITE_EA
        const NFA_RIGHT_EXECUTE = 0x00000020; //FILE_EXECUTE
        const NFA_RIGHT_READATTRIBUTES = 0x00000080; //FILE_READ_ATTRIBUTES
        const NFA_RIGHT_WRITEATTRIBUTES = 0x00000100; //FILE_WRITE_ATTRIBUTES
        const NFA_RIGHT_WRITEOWNPROPERTY = 0x00000200;
        const NFA_RIGHT_DELETEOWNITEM = 0x00000400;
        const NFA_RIGHT_VIEWITEM = 0x00000800;
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
        const FA_RIGHT_LISTCONTENTS = 0x00000001; //FILE_LIST_DIRECTORY
        const FA_RIGHT_CREATEITEM = 0x00000002; //FILE_ADD_FILE
        const FA_RIGHT_CREATECONTAINER = 0x00000004; //FILE_ADD_SUBDIRECTORY
        const FA_RIGHT_READPROPERTY = 0x00000008; //FILE_READ_EA
        const FA_RIGHT_WRITEPROPERTY = 0x00000010; //FILE_WRITE_EA
        const FA_RIGHT_READATTRIBUTES = 0x00000080; //FILE_READ_ATTRIBUTES
        const FA_RIGHT_WRITEATTRIBUTES = 0x00000100; //FILE_WRITE_ATTRIBUTES
        const FA_RIGHT_WRITEOWNPROPERTY  = 0x00000200;
        const FA_RIGHT_DELETEOWNITEM = 0x00000400;
        const FA_RIGHT_VIEWITEM = 0x00000800;
        const FA_RIGHT_OWNER = 0x00004000;
        const FA_RIGHT_CONTACT = 0x00008000;
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
