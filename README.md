# winstructs
Windows Structures in Rust

## Change Log
#### rwinstructs 0.3.2 (2017-10-14)
- Use buffers instead of reader for the following structs:
  - SubAuthorityList
  - SubAuthority
  - SecDescHeader

#### rwinstructs 0.3.1 (2017-09-18)
- Cleaned up serialization for SecurityDescriptor

#### rwinstructs 0.3.0 (2017-09-14)
- Added Clone impl for all Security Structures

#### rwinstructs 0.2.0 (2017-08-28)
- Added Security Structures
  - SecurityDescriptor
  - Acl
  - Ace
  - Sid
