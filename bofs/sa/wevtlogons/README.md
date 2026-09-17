# wevtlogons

Reads a bounded newest-first set of Security events 4624, 4625, and 4672 through Windows Event Log. Security-log access normally requires elevation.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery
- T1087.001 - Account Discovery: Local Account

## Arguments

- Optional packed int: maximum events from 1 through 256. Default is 64.

## Build

```text
cd bofs/sa/wevtlogons
cargo make
```

## Example

```text
beacon> wevtlogons <packed-arguments>
event=<value> | account=<value>\<value> | type=<value> | workstation=<value> | address=<value>
Events examined: <value> | shown: <value> | render skips: <value>
Recent Windows Security logon events | limit=<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
