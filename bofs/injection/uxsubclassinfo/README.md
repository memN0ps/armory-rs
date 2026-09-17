# uxsubclassinfo

Injects shellcode into a remote process using the UxSubclassInfo window subclass injection technique. This variant manipulates the `UxSubclassInfo` property of a target window to redirect execution flow by overwriting the subclass callback pointer with the address of injected shellcode. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> UxSubclassInfo-based technique.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/uxsubclassinfo
cargo make
```

## Example

```text
beacon> uxsubclassinfo <packed-arguments>
SUCCESS - uxsubclassinfo injection variant, remote thread created.
uxsubclassinfo injection:
sc_len:   <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
