# routeprint

Lists local network interfaces and the IPv4 routing table.

## MITRE ATT&CK

- T1016 - System Network Configuration Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/routeprint
cargo make
```

## Example

```text
beacon> inline-execute /path/to/routeprint.x64.o
===========================================================================
0x<value> ........................... <value>
<value><value><value><value><value>
```
