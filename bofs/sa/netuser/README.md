# netuser

Gets detailed information for a specific user using NetUserGetInfo (level 2).

## MITRE ATT&CK

- T1087.002 - Account Discovery: Domain Account

## Arguments

- `str`: Username (required).
- `str`: Hostname (empty to query the domain controller).

## Build

```text
cd bofs/sa/netuser
cargo make
```

## Example

```text
beacon> netuser <packed-arguments>
NetUserGetInfo returned null buffer
User info for '<value>' on <value>:
<value> 0x<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
