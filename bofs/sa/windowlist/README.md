# windowlist

Lists top-level desktop window titles and whether each window is visible.

## MITRE ATT&CK

- T1010 - Application Window Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/windowlist
cargo make
```

## Example

```text
beacon> inline-execute /path/to/windowlist.x64.o
<value> : <value>
```
