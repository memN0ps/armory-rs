# tasklist

Enumerates local processes with process ID, parent process ID, session, and image name.

## MITRE ATT&CK

- T1057 - Process Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/tasklist
cargo make
```

## Example

```text
beacon> inline-execute /path/to/tasklist.x64.o
Process inventory
<value> <value> <value> <value>
<value> <value> <value> <value>
```
