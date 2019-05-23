# winstructs
This contains some parsers for structures that are common across windows formats.

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