use byteorder::{ReadBytesExt, ByteOrder, LittleEndian, BigEndian};
use serde::{ser};
use guid::{Guid};
use utils;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::{Seek,SeekFrom};
use std::io::Cursor;

pub fn check_acl(acl_option: &Option<Acl>)->bool{
    match *acl_option {
        Some(ref acl) => {
            if acl.count > 0 {
                false
            } else {
                true
            }
        },
        None => {
            true
        }
    }
}

#[derive(Debug,Clone)]
pub enum SdErrorKind {
    IoError,
    ValidationError
}

#[derive(Debug,Clone)]
pub struct SecDescError {
    pub message: String,
    pub kind: SdErrorKind,
    pub trace: String
}
impl From<io::Error> for SecDescError {
    fn from(err: io::Error) -> Self {
        SecDescError {
            message: format!("{}",err),
            kind: SdErrorKind::IoError,
            trace: backtrace!()
        }
    }
}

#[derive(Serialize,Debug,Clone)]
pub struct SecurityDescriptor {
    #[serde(skip_serializing)]
    pub header: SecDescHeader,
    pub owner_sid: Sid,
    pub group_sid: Sid,
    #[serde(skip_serializing_if = "check_acl")]
    pub dacl: Option<Acl>,
    #[serde(skip_serializing_if = "check_acl")]
    pub sacl: Option<Acl>
}
impl SecurityDescriptor {
    pub fn new<Rs: Read+Seek>(mut reader: Rs) -> Result<SecurityDescriptor,SecDescError> {
        let _offset = reader.seek(SeekFrom::Current(0))?;

        let mut header_buff = [0; 20];
        reader.read_exact(&mut header_buff)?;

        let header = SecDescHeader::new(
            &header_buff
        )?;
        reader.seek(
            SeekFrom::Start(_offset + header.owner_sid_offset as u64)
        )?;
        let owner_sid = Sid::new(&mut reader)?;

        reader.seek(
            SeekFrom::Start(_offset + header.group_sid_offset as u64)
        )?;
        let group_sid = Sid::new(&mut reader)?;

        let dacl = match header.dacl_offset > 0 {
            true => {
                debug!("dacl at offset: {}",_offset + header.dacl_offset as u64);
                reader.seek(
                    SeekFrom::Start(_offset + header.dacl_offset as u64)
                )?;
                Some(Acl::new(&mut reader)?)
            },
            false => None
        };

        let sacl = match header.sacl_offset > 0 {
            true => {
                debug!("sacl at offset: {}",_offset + header.sacl_offset as u64);
                reader.seek(
                    SeekFrom::Start(_offset + header.sacl_offset as u64)
                )?;
                Some(Acl::new(&mut reader)?)
            },
            false => None
        };

        Ok(
            SecurityDescriptor {
                header: header,
                owner_sid: owner_sid,
                group_sid: group_sid,
                dacl: dacl,
                sacl: sacl
            }
        )
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
        write!(f,"{}",self.bits())
    }
}
impl ser::Serialize for SdControlFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

#[derive(Serialize,Debug,Clone)]
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
    pub dacl_offset: u32
}
impl SecDescHeader {
    pub fn new(buffer: &[u8]) -> Result<SecDescHeader,SecDescError> {
        let revision_number = buffer[0];
        let padding1 = buffer[1];
        let control_flags = SdControlFlags::from_bits_truncate(
            LittleEndian::read_u16(&buffer[2..4])
        );
        let owner_sid_offset = LittleEndian::read_u32(&buffer[4..8]);
        let group_sid_offset = LittleEndian::read_u32(&buffer[8..12]);

        // Does sacl offset or dacl offset come first??
        // logicly and Zimmerman's 010 Template show dacl come first
        // but libyal and msdn documentation show dacl comes first
        // https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-descriptor-header
        let sacl_offset = LittleEndian::read_u32(&buffer[12..16]);
        let dacl_offset = LittleEndian::read_u32(&buffer[16..20]);

        Ok(
            SecDescHeader {
                revision_number: revision_number,
                padding1: padding1,
                control_flags: control_flags,
                owner_sid_offset: owner_sid_offset,
                group_sid_offset: group_sid_offset,
                sacl_offset: sacl_offset,
                dacl_offset: dacl_offset
            }
        )
    }
}
#[test]
fn sec_desc_header() {
    let buffer: &[u8] = &[
        0x01,0x00,0x04,0x98,0x98,0x00,0x00,0x00,0xA4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x14,0x00,0x00,0x00,0x02,0x00
    ];

    let header = match SecDescHeader::new(&buffer) {
        Ok(header) => header,
        Err(error) => panic!(error)
    };

    assert_eq!(header.revision_number,1);
    assert_eq!(header.padding1,0);
    //assert_eq!(header.control_flags.bits(),38916);
    assert_eq!(header.owner_sid_offset,152);
    assert_eq!(header.group_sid_offset,164);
    assert_eq!(header.sacl_offset,0);
    assert_eq!(header.dacl_offset,20);
}

// ACE
// https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-entry-ace
// ACE Types
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 0x08;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x0a;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0b;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0c;
const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8 = 0x0d;
const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8 = 0x0e;
const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0f;
const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x10;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;

#[derive(Clone)]
pub struct AceType(pub u8);
impl AceType {
    pub fn as_string(&self)->String{
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
            _ => format!("UNHANDLED_TYPE: 0x{:02X}",self.0)
        }
    }
    pub fn as_u8(&self)->u8{
        self.0
    }
}
impl fmt::Display for AceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.as_string())
    }
}
impl fmt::Debug for AceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.as_string())
    }
}
impl ser::Serialize for AceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(&self.as_string())
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
        write!(f,"{}",self.bits())
    }
}
impl ser::Serialize for AceFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
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
        write!(f,"{}",self.bits())
    }
}
impl ser::Serialize for StandardAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
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
        write!(f,"{}",self.bits())
    }
}
impl ser::Serialize for NonFolderAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
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
        write!(f,"{}",self.bits())
    }
}
impl ser::Serialize for FolderAccessFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

// ACL
// https://github.com/libyal/libfwnt/wiki/Security-Descriptor#access-control-list-acl
#[derive(Serialize,Debug,Clone)]
pub struct Acl {
    pub revision: u8,
    #[serde(skip_serializing)]
    pub padding1: u8,
    #[serde(skip_serializing)]
    pub size: u16,
    pub count: u16,
    #[serde(skip_serializing)]
    pub padding2: u16,
    pub entries: Vec<Ace>
}
impl Acl{
    pub fn new<R: Read>(mut reader: R) -> Result<Acl,SecDescError> {
        let revision = reader.read_u8()?;
        let padding1 = reader.read_u8()?;
        let size = reader.read_u16::<LittleEndian>()?;
        let count = reader.read_u16::<LittleEndian>()?;
        let padding2 = reader.read_u16::<LittleEndian>()?;
        let mut entries: Vec<Ace> = Vec::new();

        for i in 0..count {
            let ace = Ace::new(&mut reader)?;
            entries.push(ace);
        }

        Ok(
            Acl {
                revision: revision,
                padding1: padding1,
                size: size,
                count: count,
                padding2: padding2,
                entries: entries
            }
        )
    }
}

#[derive(Serialize,Debug,Clone)]
pub struct Ace {
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    #[serde(skip_serializing)]
    pub size: u16,
    pub data: AceData
}
impl Ace {
    pub fn new<R: Read>(mut reader: R) -> Result<Ace,SecDescError> {
        let ace_type = AceType(reader.read_u8()?);
        let ace_flags = AceFlags::from_bits_truncate(
            reader.read_u8()?
        );
        let size = reader.read_u16::<LittleEndian>()?;

        // Create data buffer
        let mut data_buffer = vec![0;(size - 4) as usize];
        reader.read_exact(&mut data_buffer)?;

        // Get data structure
        let data = match ace_type.as_u8() {
            ACCESS_ALLOWED_ACE_TYPE |
            ACCESS_DENIED_ACE_TYPE |
            SYSTEM_AUDIT_ACE_TYPE |
            SYSTEM_ALARM_ACE_TYPE |
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE |
            ACCESS_DENIED_CALLBACK_ACE_TYPE |
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE |
            SYSTEM_ALARM_CALLBACK_ACE_TYPE |
            SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
                AceData::Basic(
                    AceBasic::new(
                        Cursor::new(data_buffer)
                    )?
                )
            },
            ACCESS_ALLOWED_OBJECT_ACE_TYPE |
            ACCESS_DENIED_OBJECT_ACE_TYPE |
            SYSTEM_AUDIT_OBJECT_ACE_TYPE |
            SYSTEM_ALARM_OBJECT_ACE_TYPE |
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE |
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE |
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE |
            SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => {
                AceData::Object(
                    AceObject::new(
                        Cursor::new(data_buffer)
                    )?
                )
            },
            // Unknown data structures
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                AceData::Unhandled(
                    RawAce(data_buffer)
                )
            },
            _ => {
                AceData::Unhandled(
                    RawAce(data_buffer)
                )
            }
        };

        Ok(
            Ace {
                ace_type: ace_type,
                ace_flags: ace_flags,
                size: size,
                data: data
            }
        )
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum AceData {
    Basic(AceBasic),
    Object(AceObject),
    Unhandled(RawAce)
}

#[derive(Serialize,Debug,Clone)]
pub struct AceBasic {
    pub access_rights: u32,
    pub sid: Sid
}
impl AceBasic {
    pub fn new<R: Read>(mut reader: R) -> Result<AceBasic,SecDescError> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let sid = Sid::new(&mut reader)?;

        Ok(
            AceBasic{
                access_rights: access_rights,
                sid: sid
            }
        )
    }
}

#[derive(Serialize,Debug,Clone)]
pub struct AceObject {
    pub access_rights: u32,
    pub flags: u32,
    pub object_type: Guid,
    pub inherited_type: Guid,
    pub sid: Sid
}
impl AceObject {
    pub fn new<R: Read>(mut reader: R) -> Result<AceObject,SecDescError> {
        let access_rights = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;
        let object_type = Guid::new(&mut reader)?;
        let inherited_type = Guid::new(&mut reader)?;
        let sid = Sid::new(&mut reader)?;

        Ok(
            AceObject{
                access_rights: access_rights,
                flags: flags,
                object_type: object_type,
                inherited_type: inherited_type,
                sid: sid
            }
        )
    }
}

#[derive(Clone)]
pub struct RawAce(pub Vec<u8>);
impl fmt::Debug for RawAce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}",
            utils::to_hex_string(&self.0),
        )
    }
}
impl ser::Serialize for RawAce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(&format!("{}", utils::to_hex_string(
            &self.0
        )))
    }
}

// SID
// https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-identifier
#[derive(Debug,Clone)]
 pub struct Sid {
     revision_number: u8,
     sub_authority_count: u8,
     authority: Authority,
     sub_authorities: SubAuthorityList
 }
 impl Sid {
     pub fn new<R: Read>(mut reader: R) -> Result<Sid,SecDescError> {
         let revision_number = reader.read_u8()?;
         let sub_authority_count = reader.read_u8()?;

         let mut buf_authority = [0;6];
         reader.read_exact(&mut buf_authority)?;
         let authority = Authority::new(
             &buf_authority
         )?;

         let sub_authorities = SubAuthorityList::new(
             &mut reader,
             sub_authority_count
         )?;

         Ok(
             Sid {
                 revision_number: revision_number,
                 sub_authority_count: sub_authority_count,
                 authority: authority,
                 sub_authorities: sub_authorities
             }
         )
     }

     pub fn to_string(&self)->String {
         format!(
             "S-{}-{}-{}",self.revision_number,self.authority,
             self.sub_authorities.to_string()
         )
     }
 }
 impl fmt::Display for Sid {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         write!(f,"{}",self.to_string())
     }
 }
 impl ser::Serialize for Sid {
     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
         where S: ser::Serializer
     {
         serializer.serialize_str(&format!("{}", self.to_string()))
     }
 }

#[derive(Serialize,Debug,Clone)]
pub struct Authority(u64);
impl Authority {
    pub fn new(buffer: &[u8]) -> Result<Authority,SecDescError> {
        let value = BigEndian::read_u64(&[
            &[0x00,0x00],
            &buffer[0..6]
        ].concat());

        Ok(
            Authority(value)
        )
    }
}
impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.0)
    }
}
#[test]
fn authority() {
    let buffer: &[u8] = &[
        0x00,0x00,0x00,0x00,0x00,0x05
    ];

    let authority = match Authority::new(&buffer) {
        Ok(authority) => authority,
        Err(error) => panic!(error)
    };

    assert_eq!(authority.0,5);
}


#[derive(Serialize,Debug,Clone)]
pub struct SubAuthorityList(Vec<SubAuthority>);
impl SubAuthorityList {
    pub fn new<R: Read>(mut reader: R, count: u8) -> Result<SubAuthorityList,SecDescError> {
        let mut list: Vec<SubAuthority> = Vec::new();

        for i in 0..count {
            let mut buf_sa = [0;4];
            reader.read_exact(&mut buf_sa)?;
            let sub = SubAuthority::new(&buf_sa)?;
            list.push(sub);
        }

        Ok(
            SubAuthorityList(list)
        )
    }

    pub fn to_string(&self)->String{
        let mut s_vec: Vec<String> = Vec::new();
        for sa in &self.0 {
            s_vec.push(sa.to_string())
        }
        format!("{}",s_vec.join("-"))
    }
}

#[derive(Serialize,Debug,Clone)]
pub struct SubAuthority(u32);
impl SubAuthority {
    pub fn new(buffer: &[u8]) -> Result<SubAuthority,SecDescError> {
        Ok(
            SubAuthority(
                LittleEndian::read_u32(&buffer[0..4])
            )
        )
    }

    pub fn to_string(&self)->String{
        format!("{}",self.0)
    }
}
impl fmt::Display for SubAuthority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.0)
    }
}
#[test]
fn sub_authority() {
    let buffer: &[u8] = &[
        0x12,0x00,0x00,0x00
    ];

    let sub_authority = match SubAuthority::new(&buffer) {
        Ok(sub_authority) => sub_authority,
        Err(error) => panic!(error)
    };

    assert_eq!(sub_authority.0,18);
}

#[test]
fn sid_test_01() {
    let buffer: &[u8] = &[
        0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00
    ];

    let sid = match Sid::new(Cursor::new(buffer)) {
        Ok(sid) => sid,
        Err(error) => panic!(error)
    };

    assert_eq!(format!("{}",sid),"S-1-5-18");
}
