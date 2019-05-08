//! This module provides utilities for reading various NT timestamp formats.

use byteorder::{LittleEndian, ReadBytesExt}; //Reading little endian data structs
use chrono::{DateTime, NaiveDate, Utc};
use serde::ser;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display};
use std::io::{self, Read};
use time::Duration;

pub static mut TIMESTAMP_FORMAT: &'static str = "%Y-%m-%d %H:%M:%S%.3f";
pub static mut DATE_FORMAT: &'static str = "%Y-%m-%d";

#[derive(Clone)]
/// https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-filetime
/// Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
/// # Example
///
/// ```
/// # use winstructs::timestamp::WinTimestamp;
/// let raw_timestamp: &[u8] = &[0x53, 0xC7, 0x8B, 0x18, 0xC5, 0xCC, 0xCE, 0x01];
///
/// let timestamp = WinTimestamp::from_reader(raw_timestamp).unwrap();
///
/// assert_eq!(format!("{}", timestamp), "2013-10-19 12:16:53.276040");
/// assert_eq!(format!("{:?}", timestamp), "2013-10-19 12:16:53.276040");
/// ```
pub struct WinTimestamp(u64);

impl WinTimestamp {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<WinTimestamp, io::Error> {
        let win_timestamp = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        Ok(win_timestamp)
    }

    pub fn to_datetime(&self) -> DateTime<Utc> {
        let nanos_since_windows_epoch = self.0;

        // Add microseconds to timestamp via Duration
        DateTime::from_utc(
            NaiveDate::from_ymd(1601, 1, 1).and_hms_nano(0, 0, 0, 0)
                + Duration::microseconds((nanos_since_windows_epoch / 10) as i64),
            Utc,
        )
    }
}

impl Display for WinTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_datetime())
    }
}

impl Debug for WinTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_datetime())
    }
}

#[derive(Clone)]
/// MS-DOS date and MS-DOS time are packed 16-bit values that specify the month, day, year, and time of day an MS-DOS file was last written to.
pub struct DosDate(u16);

impl DosDate {
    pub fn new(date: u16) -> Self {
        DosDate(date)
    }

    pub fn from_reader<R: Read>(mut buffer: R) -> Result<DosDate, io::Error> {
        Ok(DosDate::new(buffer.read_u16::<LittleEndian>()?))
    }

    pub fn to_date(&self) -> chrono::NaiveDate {
        let mut day = self.0 & 0x1F;

        if day == 0 {
            day = 1
        }

        let mut month = (self.0 >> 5) & 0x0F;

        if month == 0 {
            month = 1
        }

        let year = (self.0 >> 9) + 1980;

        chrono::NaiveDate::from_ymd(i32::from(year), u32::from(month), u32::from(day))
    }

    pub fn to_date_formatted(&self, format: &str) -> String {
        self.to_date().format(format).to_string()
    }
}

impl Display for DosDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_date())
    }
}

impl Debug for DosDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_date())
    }
}

impl ser::Serialize for DosDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_date().to_string())
    }
}

#[derive(Clone)]
/// MS-DOS date and MS-DOS time are packed 16-bit values that specify the month, day, year, and time of day an MS-DOS file was last written to.
pub struct DosTime(pub u16);
impl DosTime {
    pub fn new<R: Read>(mut buffer: R) -> Result<DosTime, Box<dyn Error>> {
        let dos_time = DosTime(buffer.read_u16::<LittleEndian>().unwrap());
        Ok(dos_time)
    }

    pub fn to_time(&self) -> chrono::NaiveTime {
        let sec = (self.0 & 0x1F) * 2;
        let min = (self.0 >> 5) & 0x3F;
        let hour = (self.0 >> 11) & 0x1F;

        chrono::NaiveTime::from_hms(u32::from(hour), u32::from(min), u32::from(sec))
    }
}

impl Display for DosTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_time())
    }
}

impl Debug for DosTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_time())
    }
}

impl ser::Serialize for DosTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&format!("{}", self.to_time()))
    }
}

#[derive(Clone)]
pub struct DosDateTime(pub u32);

impl DosDateTime {
    pub fn new<R: Read>(mut buffer: R) -> Result<DosDateTime, Box<dyn Error>> {
        let dos_datetime = DosDateTime(buffer.read_u32::<LittleEndian>()?);

        Ok(dos_datetime)
    }

    pub fn to_datetime(&self) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::new(
            DosDate((self.0 & 0xffff) as u16).to_date(),
            DosTime((self.0 >> 16) as u16).to_time(),
        )
    }
}

impl Display for DosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_datetime())
    }
}
impl Debug for DosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_datetime())
    }
}

#[cfg(test)]
mod tests {
    use crate::timestamp::{DosDate, DosDateTime, DosTime, WinTimestamp};

    #[test]
    fn test_win_timestamp() {
        let raw_timestamp: &[u8] = &[0x53, 0xC7, 0x8B, 0x18, 0xC5, 0xCC, 0xCE, 0x01];

        let timestamp = WinTimestamp::from_reader(raw_timestamp).unwrap();

        assert_eq!(format!("{}", timestamp), "2013-10-19 12:16:53.276040");
        assert_eq!(format!("{:?}", timestamp), "2013-10-19 12:16:53.276040");
    }

    #[test]
    fn test_dosdate() {
        let dos_date = DosDate(16492);

        assert_eq!(format!("{:?}", dos_date), "2012-03-12");
        assert_eq!(dos_date.0, 16492);
    }

    #[test]
    fn test_dosdate_zeros() {
        let raw_date: &[u8] = &[0x00, 0x00];
        let date = DosDate::from_reader(raw_date).unwrap();
        assert_eq!(format!("{}", date), "1980-01-01");
        assert_eq!(format!("{:?}", date), "1980-01-01");
        assert_eq!(date.0, 0);
    }

    #[test]
    fn test_dostime() {
        let dos_time = DosTime(43874);

        assert_eq!(format!("{:?}", dos_time), "21:27:04");
        assert_eq!(dos_time.0, 43874);
    }

    #[test]
    fn test_dostime_zeros() {
        let raw_time: &[u8] = &[0x00, 0x00];
        let time = DosTime::new(raw_time).unwrap();
        assert_eq!(format!("{}", time), "00:00:00");
        assert_eq!(format!("{:?}", time), "00:00:00");
        assert_eq!(time.0, 0);
    }

    #[test]
    fn test_dosdatetime() {
        let dos_time = DosDateTime(2_875_342_956);

        assert_eq!(format!("{:?}", dos_time), "2012-03-12 21:27:04");
        assert_eq!(dos_time.0, 2_875_342_956);
    }
}
