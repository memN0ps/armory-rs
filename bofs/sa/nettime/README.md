# nettime

Displays the local time on a remote computer using NetRemoteTOD.

## MITRE ATT&CK

- T1124 - System Time Discovery

## Arguments

- `str`: Hostname (empty for localhost). Uses wide string internally.

## Build

```text
cd bofs/sa/nettime
cargo make
```

## Example

```text
beacon> nettime <packed-arguments>
Local time (GMT<value>:00) at <value> is <value>/<value>/<value> <value>:<value>:<value>
Unable to retrieve time remotely: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
