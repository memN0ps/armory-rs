# findLoadedModule

Searches all running processes for a specific loaded module (DLL). Enumerates processes via CreateToolhelp32Snapshot and checks each process's module list for a case-insensitive match.

## MITRE ATT&CK

- T1057 - Process Discovery

## Arguments

- `str`: Module name to search for (e.g., `ntdll.dll`, `amsi.dll`).
- `str`: Process name filter (optional, empty for all processes).

## Build

```text
cd bofs/sa/findLoadedModule
cargo make
```

## Example

```text
beacon> findLoadedModule <packed-arguments>
Enumerated all processes but didn't find module '<value>'
Unable to list processes: <value>
<value> : <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
