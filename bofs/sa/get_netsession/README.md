# get_netsession

Enumerates network sessions on a local or remote computer using NetSessionEnum.

## MITRE ATT&CK

- T1049 - System Network Connections Discovery

## Arguments

- `str`: Hostname (empty for localhost). Uses wide string internally.

## Build

```text
cd bofs/sa/get_netsession
cargo make
```

## Example

```text
beacon> get_netsession <packed-arguments>
Network sessions at <value>:
<value> <value> <value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
