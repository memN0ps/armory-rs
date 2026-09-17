# uptime

Displays system uptime, current local time, and boot time.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/uptime
cargo make
```

## Example

```text
beacon> inline-execute /path/to/uptime.x64.o
Uptime: <value> days, <value> hours, <value> minutes, <value> seconds
Local time: <value>-<value>-<value> <value>:<value>:<value>
Boot time: <value>-<value>-<value> <value>:<value>:<value>
```
