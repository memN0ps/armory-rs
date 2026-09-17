# tooltip

Injects shellcode into a remote process using a tooltip window-based injection technique. This variant locates tooltip windows in the target process and injects shellcode via window message manipulation, abusing the tooltip control's internal data structures. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> tooltip-based technique.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/tooltip
cargo make
```

## Example

```text
beacon> tooltip <packed-arguments>
SUCCESS - tooltip injection variant, remote thread created.
tooltip injection:
sc_len:   <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
