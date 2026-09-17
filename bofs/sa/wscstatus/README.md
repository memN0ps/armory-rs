# wscstatus

Queries aggregate Windows Security Center health for each documented provider category. This reports the state seen by Security Center rather than inferring protection from a process or service name.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/wscstatus
cargo make
```

## Example

```text
beacon> inline-execute /path/to/wscstatus.x64.o
WscGetSecurityProviderHealth is unavailable
Security Center service: not available
Windows Security Center health
```
