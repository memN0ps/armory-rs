# netloggedon

Enumerates logged-on users on a local or remote computer using NetWkstaUserEnum.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery

## Arguments

- `str`: Hostname (empty for localhost). Uses wide string internally.

## Build

```text
cd bofs/sa/netloggedon
cargo make
```

## Example

```text
beacon> netloggedon <packed-arguments>
<value> <value> <value> <value>
Logged on users at <value>:
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
