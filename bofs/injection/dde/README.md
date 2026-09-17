# dde

Injects shellcode into a remote process using DDE protocol-based injection.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID.
- `bin`: Shellcode to inject.

## Build

```text
cd bofs/injection/dde
cargo make
```

## Example

```text
beacon> dde <packed-arguments>
SUCCESS: Shellcode injected via DDE protocol-based injection
DDE protocol-based injection into PID: <value>
Shellcode size: <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
