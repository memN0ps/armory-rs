# eventchannels

Enumerates local Windows Event Log channel names and configured enabled state. An optional case-insensitive substring limits the output.

## MITRE ATT&CK

- T1518.001 - Security Software Discovery

## Arguments

- Optional `str`: Channel-name filter. Empty or absent lists all channels.

## Build

```text
cd bofs/sa/eventchannels
cargo make
```

## Example

```text
beacon> eventchannels <packed-arguments>
Windows Event Log channel inventory
Channels examined: <value> | shown: <value><value>
Filter: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
