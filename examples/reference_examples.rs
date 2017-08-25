extern crate serde_json;
extern crate rwinstructs;
extern crate byteorder;
use rwinstructs::serialize;
use rwinstructs::serialize::{U64Serialization};
use rwinstructs::reference;
use rwinstructs::reference::{MftReference};
use byteorder::{ByteOrder, LittleEndian};

fn main(){
    let raw_reference: &[u8] = &[0x73,0x00,0x00,0x00,0x00,0x00,0x68,0x91];
    let mft_reference = MftReference(
        LittleEndian::read_u64(&raw_reference[0..8])
    );

    unsafe{serialize::U64_SERIALIZATION = U64Serialization::AsU64;}
    println!("{}",serde_json::to_string(&mft_reference).unwrap());

    unsafe{serialize::U64_SERIALIZATION = U64Serialization::AsString;}
    println!("{}",serde_json::to_string(&mft_reference).unwrap());

    unsafe{reference::NESTED_REFERENCE = true;}
    unsafe{serialize::U64_SERIALIZATION = U64Serialization::AsU64;}
    println!("{}",serde_json::to_string(&mft_reference).unwrap());

    unsafe{serialize::U64_SERIALIZATION = U64Serialization::AsString;}
    println!("{}",serde_json::to_string(&mft_reference).unwrap());
}
