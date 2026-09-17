# global_unprotect

Reads and decrypts GlobalProtect VPN configuration files from `%ProgramData%\Palo Alto Networks\GlobalProtect\`. Searches for portal/gateway config files and decrypts any DPAPI-protected values using CryptUnprotectData.

## MITRE ATT&CK

- T1555 - Credentials from Password Stores

## Arguments

No arguments.

## Build

```text
cd bofs/remote/global_unprotect
cargo make
```

## Example

```text
beacon> inline-execute /path/to/global_unprotect.x64.o
SUCCESS.
global_unprotect: Reading GlobalProtect VPN config files
Checked <value> config files, found <value> credential artifact(s)
```
