# createremotethread

Injects shellcode into a remote process using the classic `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `CreateRemoteThread` technique.

## MITRE ATT&CK

- T1055.001 - Process Injection: Dynamic-link Library Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/createremotethread
cargo make
```

## Example

```text
beacon> createremotethread <packed-arguments>
SUCCESS - remote thread created.
createremotethread:
sc_len:   <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
