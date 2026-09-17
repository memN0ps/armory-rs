# resources

Reports physical-memory use and free and total space for the current drive.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/resources
cargo make
```

## Example

```text
beacon> inline-execute /path/to/resources.x64.o
Error fetching disk space
Memory Used: <value>MB/<value>MB
Error fetching memory
```
