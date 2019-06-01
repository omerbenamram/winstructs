[![Build Status](https://dev.azure.com/benamram/DFIR/_apis/build/status/omerbenamram.winstructs?branchName=master)](https://dev.azure.com/benamram/DFIR/_build/latest?definitionId=6&branchName=master)
![crates.io](https://img.shields.io/crates/v/winstructs.svg)

# winstructs
This crate contains definitions and some parsing logic for structures that are common across windows formats.

Consult the [Documentation](https://docs.rs/winstructs) for supported structs and usage instructions.

### Example
Here is an example for parsing a [GUID](https://docs.microsoft.com/en-us/previous-versions/aa373931(v%3Dvs.80)).

```rust
use winstructs::guid::Guid;

fn main() {
   let raw_guid: &[u8] = &[0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
                           0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd];
                           
   let guid = Guid::from_buffer(raw_guid).unwrap();
   assert_eq!(format!("{}", guid), "54849625-5478-4994-A5BA-3E3B0328C30D");
}
```
