# netuptime

Displays the boot time of a remote computer using NetStatisticsGet.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

- `str`: Hostname (empty for localhost). Uses wide string internally.

## Build

```text
cd bofs/sa/netuptime
cargo make
```

## Example

```text
beacon> netuptime <packed-arguments>
Boot time:    <value>-<value>-<value> <value>:<value>:<value>
Unable to retrieve uptime remotely: <value>
ServerName:   <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
