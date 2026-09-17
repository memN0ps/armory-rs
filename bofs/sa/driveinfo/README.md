# driveinfo

Enumerates logical drives with drive type, volume label, file system, serial number, capacity, and available space.

## MITRE ATT&CK

- T1120 - Peripheral Device Discovery
- T1083 - File and Directory Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/driveinfo
cargo make
```

## Example

```text
beacon> inline-execute /path/to/driveinfo.x64.o
volume:      unavailable (0x<value>)
serial:      <value>-<value>
space:       unavailable
```
