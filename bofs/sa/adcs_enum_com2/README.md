# adcs_enum_com2

Enumerates Active Directory Certificate Services (AD CS) CA information and templates by invoking `certutil -TCAInfo` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

No arguments.

## Build

```text
cd bofs/sa/adcs_enum_com2
cargo make
```

## Example

```text
beacon> inline-execute /path/to/adcs_enum_com2.x64.o
=== ADCS CA Info Enumeration via certutil (T1649) ===
=== ADCS CA info enumeration complete ===
certutil -TCAInfo
```
