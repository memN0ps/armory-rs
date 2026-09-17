# domaininfo

Reports local join state and discovers one domain controller, forest name, domain name, and AD site through documented NetAPI calls.

## MITRE ATT&CK

- T1016 - System Network Configuration Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/domaininfo
cargo make
```

## Example

```text
beacon> inline-execute /path/to/domaininfo.x64.o
Controller address: <value>
Domain controller: <value>
Controller site: <value>
```
