# wefstatus

Reports Windows Event Collector service state and enumerates local Windows Event Forwarding subscription names through the documented WEC API.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/wefstatus
cargo make
```

## Example

```text
beacon> inline-execute /path/to/wefstatus.x64.o
Windows Event Forwarding configuration
Subscriptions: <unavailable while the collector service is stopped>
Windows Event Collector service: not available
```
