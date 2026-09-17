# certenum

Enumerates Current User and Local Machine personal certificate stores, including subject, issuer, expiry, enhanced-key usages, SHA-1 thumbprint, and private-key presence.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates
- T1552.004 - Unsecured Credentials: Private Keys

## Arguments

No arguments.

## Build

```text
cd bofs/sa/certenum
cargo make
```

## Example

```text
beacon> inline-execute /path/to/certenum.x64.o
Personal certificate inventory
certificates shown: <value><value>
<value> personal store:
```
