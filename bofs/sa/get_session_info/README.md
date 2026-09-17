# get_session_info

Retrieves logon session information for the current process token using `LsaGetLogonSessionData`. Displays user name, authentication package, logon type, session ID, logon server, DNS domain, UPN, profile path, home directory, logon time, and password last set.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/get_session_info
cargo make
```

## Example

```text
beacon> inline-execute /path/to/get_session_info.x64.o
LsaGetLogonSessionData returned null
UserName              : <value>
AuthenticationPackage : <value>
```
