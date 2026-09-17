# processtokens

Enumerates accessible process primary tokens and reports the owning account, integrity level, and elevation state. It requests query-only handles.

## MITRE ATT&CK

- T1057 - Process Discovery
- T1033 - System Owner/User Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/processtokens
cargo make
```

## Example

```text
beacon> inline-execute /path/to/processtokens.x64.o
Process token inventory
Visible tokens: <value> | access denied: <value><value>
<value> <value> <value> <value> <value>
```
