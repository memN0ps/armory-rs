# kernelcallbacktable

Injects shellcode into a remote process using PEB KernelCallbackTable hijacking.

## MITRE ATT&CK

- T1055.012 - Process Injection

## Arguments

- `int`: Target process ID.
- `bin`: Shellcode to inject.

## Build

```text
cd bofs/injection/kernelcallbacktable
cargo make
```

## Example

```text
beacon> kernelcallbacktable <packed-arguments>
SUCCESS: Shellcode injected via PEB KernelCallbackTable hijacking
PEB KernelCallbackTable hijacking into PID: <value>
Shellcode size: <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
