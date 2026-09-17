# applocker

Reports Application Identity service state and the configured enforcement mode and rule count for each AppLocker collection.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/applocker
cargo make
```

## Example

```text
beacon> inline-execute /path/to/applocker.x64.o
AppLocker configuration
Application Identity service: not available
Summary: <value> collection key(s) present
```
