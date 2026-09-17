# conhost

Injects shellcode into a remote process using Console Host (conhost.exe) injection.

## MITRE ATT&CK

- T1055 - Process Injection

## Arguments

- `int`: Target process ID.
- `bin`: Shellcode to inject.

## Build

```text
cd bofs/injection/conhost
cargo make
```

## Example

```text
beacon> conhost <packed-arguments>
SUCCESS: Shellcode injected via Console Host (conhost.exe) injection
Console Host (conhost.exe) injection into PID: <value>
Shellcode size: <value> bytes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
