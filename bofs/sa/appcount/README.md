# appcount

Counts unique uninstall entries across the current-user and both local-machine registry views without printing application names.

## MITRE ATT&CK

- T1518 - Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/appcount
cargo make
```

## Example

```text
beacon> inline-execute /path/to/appcount.x64.o
<value>: <value> uninstall entries examined
Unique named applications: <value>
Installed application count
```
