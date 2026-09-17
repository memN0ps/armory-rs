# enumlocalsessions

Enumerates all active and disconnected local sessions on the current host using the Windows Terminal Services API (`WTSEnumerateSessionsA`). For each qualifying session, displays the session ID, window station name, domain, and username.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/enumlocalsessions
cargo make
```

## Example

```text
beacon> inline-execute /path/to/enumlocalsessions.x64.o
Enumerating local sessions...
Total active/disconnected sessions: <value>
No sessions found.
```
