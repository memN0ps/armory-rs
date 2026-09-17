# sysmonstatus

Reports Sysmon service and driver state, configured binary paths, and the operational event-channel flag without invoking Sysmon itself.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/sysmonstatus
cargo make
```

## Example

```text
beacon> inline-execute /path/to/sysmonstatus.x64.o
Sysmon status
Operational event channel: state not specified
No standard Sysmon service name was found.
```
