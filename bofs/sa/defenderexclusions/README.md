# defenderexclusions

Enumerates configured path, process, extension, and IP-address exclusions. Registry configuration is reported as configuration evidence, not proof that an exclusion is currently effective.

## MITRE ATT&CK

- T1518.001 - Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/defenderexclusions
cargo make
```

## Example

```text
beacon> inline-execute /path/to/defenderexclusions.x64.o
Microsoft Defender exclusion inventory
Configured registry state only; effective protection may differ.
<entry omitted: name exceeds 1023 UTF-16 units>
```
