use byteorder::{ReadBytesExt, LittleEndian, BigEndian};
use serde::{ser};
use std::fmt;
use std::io;
use std::fmt::Display;
use std::io::Read;
use std::io::Cursor;
use std::mem::transmute;

#[derive(Debug)]
pub enum SdErrorKind {
    IoError,
    ValidationError
}

#[derive(Debug)]
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

#[derive(Serialize,Debug)]
pub struct SecurityDescriptor {
    pub header: SecDescHeader,
    pub owner_sid: Sid,
    pub group_sid: Sid
}
impl SecurityDescriptor {
    pub fn new<Rs: Read+Seek>(mut reader: Rs) -> Result<SecurityDescriptor,SecDescError> {
        let _offset = reader.seek(SeekFrom::Current(0))?;
        let header = SecDescHeader::new(&mut reader)?;

        reader.seek(
            SeekFrom::Start(_offset + header.owner_sid_offset as u64)
        )?;
        let owner_sid = Sid::new(&mut reader)?;

        reader.seek(
            SeekFrom::Start(_offset + header.group_sid_offset as u64)
        )?;
        let group_sid = Sid::new(&mut reader)?;

        Ok(
            SecurityDescriptor {
                header: header,
                owner_sid: owner_sid,
                group_sid: group_sid
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

#[derive(Serialize,Debug)]
pub struct SecDescHeader {
    pub revision_number: u8,
    pub padding1: u8,
    pub control_flags: SdControlFlags,
    pub owner_sid_offset: u32,
    pub group_sid_offset: u32,
    pub dacl_offset: u32,
    pub sacl_offset: u32
}
impl SecDescHeader {
    pub fn new<R: Read>(mut reader: R) -> Result<SecDescHeader,SecDescError> {
        let revision_number = reader.read_u8()?;
        let padding1 = reader.read_u8()?;
        let control_flags = SdControlFlags::from_bits_truncate(
            reader.read_u16::<LittleEndian>()?
        );
        let owner_sid_offset = reader.read_u32::<LittleEndian>()?;
        let group_sid_offset = reader.read_u32::<LittleEndian>()?;
        let dacl_offset = reader.read_u32::<LittleEndian>()?;
        let sacl_offset = reader.read_u32::<LittleEndian>()?;

        Ok(
            SecDescHeader {
                revision_number: revision_number,
                padding1: padding1,
                control_flags: control_flags,
                owner_sid_offset: owner_sid_offset,
                group_sid_offset: group_sid_offset,
                dacl_offset: dacl_offset,
                sacl_offset: sacl_offset
            }
        )
    }
}

// SID
// https://github.com/libyal/libfwnt/wiki/Security-Descriptor#security-identifier
#[derive(Debug)]
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
         let authority = Authority::new(&mut reader)?;

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

#[derive(Serialize,Debug)]
pub struct Authority(u64);
impl Authority {
    pub fn new<R: Read>(mut reader: R) -> Result<Authority,SecDescError> {
        let mut buffer = vec![0;6];
        reader.read_exact(buffer.as_mut_slice())?;
        // Add last two bytes
        buffer.insert(0,0);
        buffer.insert(0,0);

        let value = Cursor::new(buffer).read_u64::<BigEndian>()?;

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

#[derive(Serialize,Debug)]
pub struct SubAuthorityList(Vec<SubAuthority>);
impl SubAuthorityList {
    pub fn new<R: Read>(mut reader: R, count: u8) -> Result<SubAuthorityList,SecDescError> {
        let mut list: Vec<SubAuthority> = Vec::new();

        for i in 0..count {
            let sub = SubAuthority::new(&mut reader)?;
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
    pub fn new<R: Read>(mut reader: R) -> Result<SubAuthority,SecDescError> {
        let value = reader.read_u32::<LittleEndian>()?;

        Ok(
            SubAuthority(value)
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
