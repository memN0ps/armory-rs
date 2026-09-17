# listmods

Enumerates all loaded modules (DLLs) in a target process using EnumProcessModulesEx and GetModuleFileNameExA. If PID 0 is specified, the current process is used.

## MITRE ATT&CK

- T1057 - Process Discovery

## Arguments

- `int`: Process identifier. Use `0` for the current process.

## Build

```text
cd bofs/sa/listmods
cargo make
```

## Example

```text
beacon> listmods <packed-arguments>
Listing modules for PID: <value>
Total modules: <value>
<value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
