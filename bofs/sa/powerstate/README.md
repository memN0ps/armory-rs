# powerstate

Reports AC and battery state, then classifies the chassis using SMBIOS Type 3 data with a battery-presence fallback.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/powerstate
cargo make
```

## Example

```text
beacon> inline-execute /path/to/powerstate.x64.o
Chassis: <value> (battery fallback)
Chassis: <value> (SMBIOS type <value>)
Power and chassis state
```
