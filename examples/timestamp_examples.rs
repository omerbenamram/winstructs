#[macro_use] extern crate serde_json;
extern crate rwinstructs;
extern crate byteorder;
use rwinstructs::timestamp;
use byteorder::{ByteOrder, LittleEndian};

fn main(){
    let raw_timestamp: &[u8] = &[0x53,0xC7,0x8B,0x18,0xC5,0xCC,0xCE,0x01];
    let time_stamp: timestamp::WinTimestamp = timestamp::raw_to_wintimestamp(raw_timestamp).unwrap();
    println!("{}", serde_json::to_string(&time_stamp).unwrap());

    unsafe{timestamp::TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S%.6f";}
    println!("{}", serde_json::to_string(&time_stamp).unwrap());
}
