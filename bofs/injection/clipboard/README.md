# clipboard

Injects shellcode into a remote process using a clipboard-based target process via `CreateRemoteThread`. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> clipboard-based technique.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/clipboard
cargo make
```

## Example

```text
beacon> clipboard <packed-arguments>
SUCCESS - clipboard injection variant, remote thread created.
clipboard injection:
sc_len:   <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
