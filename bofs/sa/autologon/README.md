# autologon

Reads the Windows Winlogon AutoAdminLogon configuration and reports any configured account and plaintext password values. It does not change the registry.

## MITRE ATT&CK

- T1552.002 - Unsecured Credentials: Credentials in Registry

## Arguments

No arguments.

## Build

```text
cd bofs/sa/autologon
cargo make
```

## Example

```text
beacon> inline-execute /path/to/autologon.x64.o
Winlogon AutoAdminLogon configuration
[*] No AutoAdminLogon values were present.
[+] Values found: <value>
```
