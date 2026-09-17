# listdns

Enumerates the local DNS resolver cache entries.

## MITRE ATT&CK

- T1018 - Remote System Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/listdns
cargo make
```

## Example

```text
beacon> inline-execute /path/to/listdns.x64.o
Cache record: <value>   | TYPE <value>
No DNS cache entries found
```
