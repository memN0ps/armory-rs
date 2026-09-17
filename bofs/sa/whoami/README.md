# whoami

Reports the current user, SID, token groups, integrity level, and token privileges.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery
- T1069.001 - Permission Groups Discovery: Local Groups

## Arguments

No arguments.

## Build

```text
cd bofs/sa/whoami
cargo make
```

## Example

```text
beacon> inline-execute /path/to/whoami.x64.o
<value> <value> <value> <value>
PRIVILEGES INFORMATION
----------------------
```
