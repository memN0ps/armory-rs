# adcs_enum_com

Enumerates Active Directory Certificate Services (AD CS) configuration using the ICertConfig2 COM interface to discover certificate authorities.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

No arguments.

## Build

```text
cd bofs/sa/adcs_enum_com
cargo make
```

## Example

```text
beacon> inline-execute /path/to/adcs_enum_com.x64.o
=== ADCS CA Enumeration via ICertConfig2 COM (T1649) ===
=== ADCS COM enumeration complete ===
Found <value> CA configuration(s)
```
