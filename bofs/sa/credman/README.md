# credman

Enumerates credentials available to the current logon session through the Windows Credential Manager API and prints bounded credential blobs.

## MITRE ATT&CK

- T1555 - Credentials from Password Stores

## Arguments

No arguments.

## Build

```text
cd bofs/sa/credman
cargo make
```

## Example

```text
beacon> inline-execute /path/to/credman.x64.o
[*] Credential Manager returned no credentials.
[*] Output limit reached; <value> entries omitted.
Credential Manager entries: <value>
```
