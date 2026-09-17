# vssenum

Enumerates Volume Shadow Copies by probing well-known shadow copy device paths (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN). This avoids COM/WMI dependencies and works by directly testing for the existence of shadow copy volumes using CreateFileA.

## MITRE ATT&CK

- T1003.003 - OS Credential Dumping: NTDS

## Arguments

No arguments.

## Build

```text
cd bofs/sa/vssenum
cargo make
```

## Example

```text
beacon> inline-execute /path/to/vssenum.x64.o
=== Volume Shadow Copy Enumeration ===
=== VSS Enumeration Complete ===
Created:       <value>
```
