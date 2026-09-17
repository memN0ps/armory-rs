# ntcreatethread

Injects shellcode into a remote process using the `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `NtCreateThreadEx` technique.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID (PID).
- `bin`: Shellcode to inject (binary data).

## Build

```text
cd bofs/injection/ntcreatethread
cargo make
```

## Example

```text
beacon> ntcreatethread <packed-arguments>
SUCCESS - remote thread created via NtCreateThreadEx.
sc_len:   <value> bytes
ntcreatethread:
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
