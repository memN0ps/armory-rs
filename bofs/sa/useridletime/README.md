# useridletime

Displays how long the current user has been idle (no keyboard/mouse input).

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/useridletime
cargo make
```

## Example

```text
beacon> inline-execute /path/to/useridletime.x64.o
Current User idle time: <value> days, <value> hours, <value> minutes, <value> seconds
```
