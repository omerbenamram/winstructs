use byteorder::{ByteOrder, LittleEndian};

use rwinstructs::reference::{MftReference};
use serde_json;

fn main() {
    let raw_reference: &[u8] = &[0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x91];
    let mft_reference = MftReference(LittleEndian::read_u64(&raw_reference[0..8]));

    println!("{}", serde_json::to_string(&mft_reference).unwrap());
}
