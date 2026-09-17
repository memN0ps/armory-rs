# winver

Reports the native Windows version, build, update build revision, product name, display version, and installation type.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/winver
cargo make
```

## Example

```text
beacon> inline-execute /path/to/winver.x64.o
Registry product label: <value>
Build and revision: <value>.<value>
Native version: <value>.<value>.<value>
```
