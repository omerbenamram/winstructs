use byteorder::{LittleEndian, ReadBytesExt}; //Reading little endian data structs
use chrono; //Datetime Handling
use serde::ser;
use std::fmt;
use std::fmt::{Debug, Display};
use std::io::Error;
use std::io::Read;
use time;

pub static mut TIMESTAMP_FORMAT: &'static str = "%Y-%m-%d %H:%M:%S%.3f";
pub static mut DATE_FORMAT: &'static str = "%Y-%m-%d";

#[derive(Clone)]
pub struct WinTimestamp(u64);

impl WinTimestamp {
    // TODO: this should be UTC, not naive.
    pub fn to_datetime(&self) -> chrono::NaiveDateTime {
        // Get nanoseconds (100-nanosecond intervals)
        let t_micro = self.0 / 10;
        // Add microseconds to timestamp via Duration
        (chrono::NaiveDate::from_ymd(
                1601, 1, 1
            ).and_hms_nano(0, 0, 0, 0) + // Win Epoc = 1601-01-01
            time::Duration::microseconds(t_micro as i64)) as chrono::NaiveDateTime
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
pub struct DosDate(u16);

impl DosDate {
    pub fn new(date: u16) -> Self {
        DosDate(date)
    }

    pub fn from_reader<R: Read>(mut buffer: R) -> Result<DosDate, Error> {
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
        serializer.serialize_str(&)
    }
}

#[derive(Clone)]
pub struct DosTime(pub u16);
impl DosTime {
    pub fn new<R: Read>(mut buffer: R) -> Result<DosTime, Error> {
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
    pub fn new<R: Read>(mut buffer: R) -> Result<DosDateTime, Error> {
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

#[allow(dead_code)]
pub fn raw_to_wintimestamp<R: Read>(mut buffer: R) -> Result<WinTimestamp, Error> {
    let win_timestamp: WinTimestamp = WinTimestamp(buffer.read_u64::<LittleEndian>().unwrap());
    Ok(win_timestamp)
}

#[cfg(test)]
mod tests {
    use crate::timestamp::{raw_to_wintimestamp, DosDate, DosDateTime, DosTime, WinTimestamp};

    #[test]
    fn test_win_timestamp() {
        let raw_timestamp: &[u8] = &[0x53, 0xC7, 0x8B, 0x18, 0xC5, 0xCC, 0xCE, 0x01];

        let time_stamp: WinTimestamp = match raw_to_wintimestamp(raw_timestamp) {
            Ok(time_stamp) => time_stamp,
            Err(error) => panic!(error),
        };

        assert_eq!(format!("{}", time_stamp), "2013-10-19 12:16:53.276040");
        assert_eq!(format!("{:?}", time_stamp), "2013-10-19 12:16:53.276040");
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
