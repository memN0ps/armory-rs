# env

Lists environment variables visible to the current Beacon process.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/env
cargo make
```

## Example

```text
beacon> inline-execute /path/to/env.x64.o
All environment variables:
<value>
```
