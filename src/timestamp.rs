//! Provides utilities for reading various NT timestamp formats.
use crate::err::Result;
use byteorder::{LittleEndian, ReadBytesExt}; //Reading little endian data structs
use chrono::{DateTime, Duration, NaiveDate, Utc};

use std::fmt;
use std::fmt::{Debug, Display};
use std::io::{Cursor, Read};

#[derive(Clone)]
/// https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-filetime
/// Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
/// # Example
///
/// ```
/// # use winstructs::timestamp::WinTimestamp;
/// let raw_timestamp: &[u8] = &[0x53, 0xC7, 0x8B, 0x18, 0xC5, 0xCC, 0xCE, 0x01];
///
/// let timestamp = WinTimestamp::new(raw_timestamp).unwrap();
///
/// assert_eq!(format!("{}", timestamp), "2013-10-19 12:16:53.276040 UTC");
/// assert_eq!(format!("{:?}", timestamp), "2013-10-19 12:16:53.276040 UTC");
/// ```
pub struct WinTimestamp(u64);

impl WinTimestamp {
    pub fn new(buffer: &[u8]) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    #[inline]
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<WinTimestamp> {
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

    pub fn from_reader<R: Read>(buffer: &mut R) -> Result<DosDate> {
        Ok(DosDate::new(buffer.read_u16::<LittleEndian>()?))
    }

    #[inline]
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

#[derive(Clone)]
/// MS-DOS date and MS-DOS time are packed 16-bit values that specify the month, day, year, and time of day an MS-DOS file was last written to.
pub struct DosTime(u16);
impl DosTime {
    pub fn new(value: u16) -> Self {
        DosTime(value)
    }

    pub fn from_reader<R: Read>(buffer: &mut R) -> Result<DosTime> {
        Ok(DosTime::new(buffer.read_u16::<LittleEndian>()?))
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

#[derive(Clone)]
pub struct DosDateTime {
    date: u16,
    time: u16,
}

impl DosDateTime {
    pub fn new(date: u16, time: u16) -> Self {
        DosDateTime { date, time }
    }
    pub fn from_reader<R: Read>(buffer: &mut R) -> Result<DosDateTime> {
        let date = buffer.read_u16::<LittleEndian>()?;
        let time = buffer.read_u16::<LittleEndian>()?;

        Ok(DosDateTime::new(date, time))
    }

    pub fn to_datetime(&self) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::new(DosDate(self.date).to_date(), DosTime(self.time).to_time())
    }
}

impl From<u32> for DosDateTime {
    fn from(datetime: u32) -> Self {
        let date = (datetime & 0xffff) as u16;
        let time = (datetime >> 16) as u16;

        DosDateTime::new(date, time)
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
    use std::io::Cursor;

    #[test]
    fn test_win_timestamp() {
        let raw_timestamp: &[u8] = &[0x53, 0xC7, 0x8B, 0x18, 0xC5, 0xCC, 0xCE, 0x01];

        let timestamp = WinTimestamp::from_reader(&mut Cursor::new(raw_timestamp)).unwrap();

        assert_eq!(format!("{}", timestamp), "2013-10-19 12:16:53.276040 UTC");
        assert_eq!(format!("{:?}", timestamp), "2013-10-19 12:16:53.276040 UTC");
    }

    #[test]
    fn test_dosdate() {
        let dos_date = DosDate(16492);

        assert_eq!(format!("{:?}", dos_date), "2012-03-12");
    }

    #[test]
    fn test_dosdate_zeros() {
        let raw_date: &[u8] = &[0x00, 0x00];
        let date = DosDate::from_reader(&mut Cursor::new(raw_date)).unwrap();
        assert_eq!(format!("{}", date), "1980-01-01");
        assert_eq!(format!("{:?}", date), "1980-01-01");
    }

    #[test]
    fn test_dostime() {
        let dos_time = DosTime(43874);

        assert_eq!(format!("{:?}", dos_time), "21:27:04");
    }

    #[test]
    fn test_dostime_zeros() {
        let raw_time: &[u8] = &[0x00, 0x00];
        let time = DosTime::from_reader(&mut Cursor::new(raw_time)).unwrap();
        assert_eq!(format!("{}", time), "00:00:00");
        assert_eq!(format!("{:?}", time), "00:00:00");
    }

    #[test]
    fn test_dosdatetime() {
        let dos_time = DosDateTime::from(2_875_342_956);

        assert_eq!(format!("{:?}", dos_time), "2012-03-12 21:27:04");
    }
}
