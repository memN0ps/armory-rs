# office_tokens

Scans an Office process's memory for JWT tokens by searching for the base64-encoded JWT prefix "eyJ". Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory.

## MITRE ATT&CK

- T1528 - Steal Application Access Token

## Arguments

- `int`: Target Office process ID.

## Build

```text
cd bofs/remote/office_tokens
cargo make
```

## Example

```text
beacon> office_tokens <packed-arguments>
SUCCESS.
office_tokens: Scanning process <value> for JWT tokens (eyJ prefix)
Scanned <value> regions, found <value> potential JWT token(s)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
