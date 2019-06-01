![crates.io](https://img.shields.io/crates/v/winstructs.svg)

# winstructs
This crate contains definitions and some parsing logic for structures that are common across windows formats.

[Documentation](https://docs.rs/winstructs) 

Currently supported formats:

- Guid
- FILETIME, DosTime (conversion to chrono)
- Windows Security IDs:
    - SecurityDescriptor
    - Acl
    - Ace
    - Sid
- NTFS:
   - MFT reference

# Note
This library was inspired by https://github.com/forensicmatt/r-winstructs, but is not API compatible in any sort.
