# netshares

Enumerates network shares on a local or remote computer using NetShareEnum. Supports both admin-level (SHARE_INFO_2) and user-level (SHARE_INFO_1) enumeration.

## MITRE ATT&CK

- T1135 - Network Share Discovery

## Arguments

- `str`: Hostname (empty for localhost). Uses wide string internally.
- `int`: Flag - 1 for admin level (SHARE_INFO_2), 0 for user level (SHARE_INFO_1).

## Build

```text
cd bofs/sa/netshares
cargo make
```

## Example

```text
beacon> netshares <packed-arguments>
Share enumeration (admin) at <value>:
Share enumeration (user) at <value>:
<value> <value> <value> <value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
