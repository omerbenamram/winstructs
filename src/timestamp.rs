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

#[allow(dead_code)]
pub fn raw_to_wintimestamp<R: Read>(mut buffer: R)->Result<WinTimestamp,Error>{
    let win_timestamp: WinTimestamp = WinTimestamp(
        buffer.read_u64::<LittleEndian>().unwrap()
    );
    Ok(win_timestamp)
}

#[test]
fn test_timestamp() {
    let raw_timestamp: &[u8] = &[0x53,0xC7,0x8B,0x18,0xC5,0xCC,0xCE,0x01];

    let time_stamp: WinTimestamp = match raw_to_wintimestamp(raw_timestamp){
        Ok(time_stamp) => time_stamp,
        Err(error) => panic!(error)
    };

    assert_eq!(format!("{}",time_stamp),"2013-10-19 12:16:53.276040");
    assert_eq!(format!("{:?}",time_stamp),"2013-10-19 12:16:53.276040");
    assert_eq!(time_stamp.0,130266586132760403);
}
