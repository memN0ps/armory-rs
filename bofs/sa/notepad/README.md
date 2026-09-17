# notepad

Finds an open Notepad window and reads text from its edit control.

## MITRE ATT&CK

- T1010 - Application Window Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/notepad
cargo make
```

## Example

```text
beacon> inline-execute /path/to/notepad.x64.o
Edit control not found in Notepad
Notepad content (<value> chars):
<value>
Notepad window not found
```
