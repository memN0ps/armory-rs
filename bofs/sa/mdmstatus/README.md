# mdmstatus

Enumerates local Windows MDM enrollment records. A record proves that enrollment data exists; it does not by itself prove that the management channel is currently healthy.

## MITRE ATT&CK

- T1012 - Query Registry
- T1518 - Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/mdmstatus
cargo make
```

## Example

```text
beacon> inline-execute /path/to/mdmstatus.x64.o
No MDM enrollment registry exists.
No MDM provider records found.
MDM enrollment records
```
