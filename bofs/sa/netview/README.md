# netview

Enumerates computers on the network using NetServerEnum.

## MITRE ATT&CK

- T1018 - Remote System Discovery

## Arguments

- `str`: Domain (empty for default domain). Uses wide string internally.

## Build

```text
cd bofs/sa/netview
cargo make
```

## Example

```text
beacon> netview <packed-arguments>
Computers on <value>:
<value> <value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
