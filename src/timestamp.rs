use chrono;                                     //Datetime Handling
use time;
use byteorder::{ReadBytesExt, LittleEndian};    //Reading little endian data structs
use std::io::{Error};
use std::fmt;
use std::fmt::{Display,Debug};
use std::io::Read;
use serde::{ser};

pub static mut TIMESTAMP_FORMAT: &'static str = "%Y-%m-%d %H:%M:%S%.3f";

#[derive(Clone)]
pub struct WinTimestamp(
    pub u64
);
impl WinTimestamp {
    pub fn to_datetime(&self) -> chrono::NaiveDateTime {
        // Get nanoseconds (100-nanosecond intervals)
        let t_micro = self.0 / 10;
        // Add microseconds to timestamp via Duration
        (
            chrono::NaiveDate::from_ymd(1601, 1, 1).and_hms_nano(0, 0, 0, 0) + // Win Epoc = 1601-01-01
            time::Duration::microseconds(t_micro as i64)
        ) as chrono::NaiveDateTime
    }
}
impl Display for WinTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_datetime())
    }
}
impl Debug for WinTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_datetime())
    }
}
impl ser::Serialize for WinTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(
            &format!("{}",
            self.to_datetime().format(unsafe{TIMESTAMP_FORMAT}).to_string())
        )
    }
}

#[derive(Clone)]
pub struct DosDate(
    pub u16
);
impl DosDate {
    pub fn new<R: Read>(mut buffer: R)->Result<DosDate,Error>{
        let dos_date = DosDate(
            buffer.read_u16::<LittleEndian>().unwrap()
        );
        Ok(dos_date)
    }

    pub fn to_date(&self) -> chrono::NaiveDate {
        let day = self.0 & 0x1F;
        let month = (self.0 >> 5) & 0x0F;
        let year = (self.0 >> 9) + 1980;

        chrono::NaiveDate::from_ymd(
            year as i32,
            month as u32,
            day as u32
        )
    }
}
impl Debug for DosDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_date())
    }
}
impl ser::Serialize for DosDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(
            &format!("{}",
            self.to_date().format(unsafe{TIMESTAMP_FORMAT}).to_string())
        )
    }
}

#[derive(Clone)]
pub struct DosTime(
    pub u16
);
impl DosTime {
    pub fn new<R: Read>(mut buffer: R)->Result<DosTime,Error>{
        let dos_time = DosTime(
            buffer.read_u16::<LittleEndian>().unwrap()
        );
        Ok(dos_time)
    }

    pub fn to_time(&self) -> chrono::NaiveTime {
        let sec = (self.0 & 0x1F) * 2;
        let min = (self.0 >> 5) & 0x3F;
        let hour = (self.0 >> 11) & 0x1F;

        chrono::NaiveTime::from_hms(
            hour as u32,
            min as u32,
            sec as u32
        )
    }
}
impl Debug for DosTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_time())
    }
}
impl ser::Serialize for DosTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(
            &format!("{}",
            self.to_time().format(unsafe{TIMESTAMP_FORMAT}).to_string())
        )
    }
}

#[derive(Clone)]
pub struct DosDateTime(
    pub u32
);
impl DosDateTime {
    pub fn new<R: Read>(mut buffer: R)->Result<DosDateTime,Error>{
        let dos_datetime = DosDateTime(
            buffer.read_u32::<LittleEndian>()?
        );

        Ok(dos_datetime)
    }

    pub fn to_datetime(&self) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::new(
            DosDate((self.0 & 0xffff) as u16).to_date(),
            DosTime((self.0 >> 16) as u16).to_time()
        )
    }
}
impl Display for DosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_datetime())
    }
}
impl Debug for DosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.to_datetime())
    }
}
impl ser::Serialize for DosDateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(
            &format!("{}",
            self.to_datetime().format(unsafe{TIMESTAMP_FORMAT}).to_string())
        )
    }
}

#[allow(dead_code)]
pub fn raw_to_wintimestamp<R: Read>(mut buffer: R)->Result<WinTimestamp,Error>{
    let win_timestamp: WinTimestamp = WinTimestamp(
        buffer.read_u64::<LittleEndian>().unwrap()
    );
    Ok(win_timestamp)
}

#[test]
fn test_wintimestamp() {
    let raw_timestamp: &[u8] = &[0x53,0xC7,0x8B,0x18,0xC5,0xCC,0xCE,0x01];

    let time_stamp: WinTimestamp = match raw_to_wintimestamp(raw_timestamp){
        Ok(time_stamp) => time_stamp,
        Err(error) => panic!(error)
    };

    assert_eq!(format!("{}",time_stamp),"2013-10-19 12:16:53.276040");
    assert_eq!(format!("{:?}",time_stamp),"2013-10-19 12:16:53.276040");
    assert_eq!(time_stamp.0,130266586132760403);
}
#[test]
fn test_dosdate() {
    let dos_date = DosDate(16492);

    assert_eq!(format!("{:?}",dos_date),"2012-03-12");
    assert_eq!(dos_date.0,16492);
}
#[test]
fn test_dostime() {
    let dos_time = DosTime(43874);

    assert_eq!(format!("{:?}",dos_time),"21:27:04");
    assert_eq!(dos_time.0,43874);
}
#[test]
fn test_dosdatetime() {
    let dos_time = DosDateTime(2875342956);

    assert_eq!(format!("{:?}",dos_time),"2012-03-12 21:27:04");
    assert_eq!(dos_time.0,2875342956);
}
