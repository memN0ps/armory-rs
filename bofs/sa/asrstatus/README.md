# asrstatus

Enumerates locally configured and policy-backed Attack Surface Reduction rules and exclusions without changing Microsoft Defender settings.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/asrstatus
cargo make
```

## Example

```text
beacon> inline-execute /path/to/asrstatus.x64.o
Attack Surface Reduction configuration
Summary: <value> configured rule value(s), <value> exclusion value(s)
<none configured>
```
