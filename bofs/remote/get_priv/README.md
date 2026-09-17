# get_priv

Enables a specified privilege on the current process or thread token. Prefix privilege name with `~` to target the thread token (useful for impersonated tokens) instead of the process token.

## MITRE ATT&CK

- T1134.002 - Access Token Manipulation: Create Process with Token

## Arguments

- `str`: Privilege name (e.g., `SeDebugPrivilege`, `~SeDebugPrivilege`).

## Build

```text
cd bofs/remote/get_priv
cargo make
```

## Example

```text
beacon> get_priv <packed-arguments>
SUCCESS: Activated priv <value>.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
