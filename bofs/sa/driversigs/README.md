# driversigs

Enumerates kernel-mode driver services and checks their binary paths against known EDR/AV vendor signatures. Helps identify security products on the target system.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/driversigs
cargo make
```

## Example

```text
beacon> inline-execute /path/to/driversigs.x64.o
Total driver services enumerated: <value>
No known EDR/AV driver signatures detected.
No driver services found or access denied.
```
