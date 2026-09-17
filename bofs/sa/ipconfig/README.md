# ipconfig

Lists local adapter, DNS, gateway, DHCP, and address configuration.

## MITRE ATT&CK

- T1016 - System Network Configuration Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/ipconfig
cargo make
```

## Example

```text
beacon> inline-execute /path/to/ipconfig.x64.o
Windows IP Configuration
<value>   <value>
<value> adapter <value>:
```
