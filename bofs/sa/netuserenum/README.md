# netuserenum

Enumerates user accounts on a local or remote computer using NetUserEnum. Supports filtering by account status: all users, locked, disabled, or active. Optionally queries a domain controller via NetGetAnyDCName when targeting a domain.

## MITRE ATT&CK

- T1087.001 - Account Discovery: Local Account
- T1087.002 - Account Discovery: Domain Account

## Arguments

- `int`: usedomain - 0 for local, 1 for domain (queries a DC via NetGetAnyDCName)
- `int`: userfilter - 1=all, 2=locked, 3=disabled, 4=active

## Build

```text
cd bofs/sa/netuserenum
cargo make
```

## Example

```text
beacon> netuserenum <packed-arguments>
User enumeration (filter: <value>):
Error: invalid userfilter <value>. Use 1=all, 2=locked, 3=disabled, 4=active.
Domain Controller: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
