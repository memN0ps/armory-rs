# token

Creates an impersonation token from explicit credentials, duplicates a token from a selected process, or reverts the current Beacon token.

## MITRE ATT&CK

- T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- T1134.003 - Access Token Manipulation: Make and Impersonate Token

## Arguments

- `str`: Action: `make`, `steal`, or `revert`.
- `make`: `str` domain, `str` username, `str` password, `int` logon type.
- `steal`: `int` process ID.

## Build

```text
cd bofs/remote/token
cargo make
```

## Example

```text
beacon> token <packed-arguments>
[+] Impersonating a duplicated token from PID <value>.
[+] Reverted to the original Beacon token.
[+] Impersonating <value> with logon type <value>.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
