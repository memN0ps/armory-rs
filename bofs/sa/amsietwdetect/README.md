# amsietwdetect

Reports whether AMSI is loaded in the current process and whether selected AMSI and ETW exports are present. It does not inspect code bytes or patch either interface.

## MITRE ATT&CK

- T1518.001 - Security Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/amsietwdetect
cargo make
```

## Example

```text
beacon> inline-execute /path/to/amsietwdetect.x64.o
AMSI and ETW presence in the current process
No code bytes were read or changed.
EtwEventWriteFull export: <value>
```
