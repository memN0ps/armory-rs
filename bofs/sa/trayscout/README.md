# trayscout

Reports the taskbar host and bounded Windows 11 notification-area metadata. It does not use undocumented Explorer toolbar structures or read another process's memory.

## MITRE ATT&CK

- T1012 - Query Registry
- T1057 - Process Discovery

## Arguments

- Optional packed string: `verbose` to include full executable paths.

## Build

```text
cd bofs/sa/trayscout
cargo make
```

## Example

```text
beacon> trayscout <packed-arguments>
Taskbar host: <not present in this desktop session>
Notification metadata unavailable: 0x<value>
Taskbar host: pid=<value> | path unavailable
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
