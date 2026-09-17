# netstat

Lists selected local TCP and UDP connection tables with owning process identifiers.

## MITRE ATT&CK

- T1049 - System Network Connections Discovery

## Arguments

- `int`: Bit mask: `0x0001` TCPv4, `0x0010` TCPv6, `0x0100` UDPv4, and `0x1000` UDPv6.

## Build

```text
cd bofs/sa/netstat
cargo make
```

## Example

```text
beacon> netstat <packed-arguments>
<value> <value> <value> <value> <value>
Active Connections
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
