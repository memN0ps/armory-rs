# svcctrl

Injects shellcode into a remote process using a service control manager-based injection technique. This variant abuses the SCM to create a temporary service that triggers shellcode execution in the target process. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> service control-based technique.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/svcctrl
cargo make
```

## Example

```text
beacon> svcctrl <packed-arguments>
SUCCESS - svcctrl injection variant, remote thread created.
svcctrl injection:
sc_len:   <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
