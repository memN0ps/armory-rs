# arp

Lists the local IPv4 ARP cache with interface indexes, MAC addresses, and entry types.

## MITRE ATT&CK

- T1016 - System Network Configuration Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/arp
cargo make
```

## Example

```text
beacon> inline-execute /path/to/arp.x64.o
No ARP entries found.
Interface  --- 0x<value>
<value><value><value>
```
