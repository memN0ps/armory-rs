# proxyenum

Reports machine WinHTTP proxy settings, the current user's WinINet proxy and automatic-configuration state, and common proxy environment variables.

## MITRE ATT&CK

- T1016 - System Network Configuration Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/proxyenum
cargo make
```

## Example

```text
beacon> inline-execute /path/to/proxyenum.x64.o
Proxy configuration
WinHTTP machine mode:   <value>
WinHTTP proxy:          <value>
```
