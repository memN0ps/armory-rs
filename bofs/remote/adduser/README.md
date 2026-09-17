# adduser

Adds a new local user account on a target host using NetUserAdd.

## MITRE ATT&CK

- T1136.001 - Create Account: Local Account

## Arguments

- `str`: Hostname (use `.` for local machine).
- `str`: Username to create.
- `str`: Password for the new account.

## Build

```text
cd bofs/remote/adduser
cargo make
```

## Example

```text
beacon> adduser <packed-arguments>
Successfully added user '<value>' on '<value>'.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
