use serde::{ser};
pub static mut U64_SERIALIZATION: U64Serialization = U64Serialization::AsU64;

pub enum U64Serialization {
    AsU64,
    AsString
}

pub fn serialize_u64<S>(&item: &u64, serializer: S) -> Result<S::Ok, S::Error> where S: ser::Serializer
{
    unsafe {
        match U64_SERIALIZATION {
            U64Serialization::AsU64 => {
                serializer.serialize_u64(item)
            },
            U64Serialization::AsString => {
                serializer.serialize_str(&format!("{}", item))
            }
        }
    }
}
