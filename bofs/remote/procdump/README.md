# procdump

Dumps process memory to a file using MiniDumpWriteDump. Enables SeDebugPrivilege before opening the target process so that privileged processes (e.g., lsass.exe) can be dumped.

## MITRE ATT&CK

- T1003.001 - OS Credential Dumping: LSASS Memory

## Arguments

- `int`: Target process ID.
- `str`: Output file path (e.g., `C:\Windows\Temp\dump.dmp`).

## Build

```text
cd bofs/remote/procdump
cargo make
```

## Example

```text
beacon> procdump <packed-arguments>
Successfully dumped process <value> to '<value>'
Enabled SeDebugPrivilege
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
