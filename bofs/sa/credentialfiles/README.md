# credentialfiles

Reports the presence and size of common developer, cloud, CI/CD, package, container, and SSH credential files for the current user. It never reads or prints file contents.

## MITRE ATT&CK

- T1552.001 - Unsecured Credentials: Credentials In Files
- T1552.004 - Unsecured Credentials: Private Keys

## Arguments

No arguments.

## Build

```text
cd bofs/sa/credentialfiles
cargo make
```

## Example

```text
beacon> inline-execute /path/to/credentialfiles.x64.o
Credential candidates: <value> | configuration files: <value> | access errors: <value>
Presence and size only; file contents are not read.
credential | SSH PEM candidate | <value> bytes | <value>
```
