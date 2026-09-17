# shspawnas

Spawns a process as another user using `CreateProcessWithLogonW`.

## MITRE ATT&CK

- T1134.002 - Access Token Manipulation: Create Process with Token

## Arguments

- `str`: Username.
- `str`: Password.
- `str`: Domain.
- `str`: Command line to execute.

## Build

```text
cd bofs/remote/shspawnas
cargo make
```

## Example

```text
beacon> shspawnas <packed-arguments>
Process spawned successfully (PID: <value>)
SUCCESS.
username: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
