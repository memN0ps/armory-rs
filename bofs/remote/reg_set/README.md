# reg_set

Sets a registry value using RegSetValueExA. Supports remote registry access via RegConnectRegistryA when a hostname is provided. Creates the key if it does not already exist using RegCreateKeyExA.

## MITRE ATT&CK

- T1112 - Modify Registry

## Arguments

- `str`: Hostname (empty for localhost).
- `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
- `str`: Registry path (subkey).
- `str`: Value name.
- `str`: Type string ("REG_SZ", "REG_DWORD", "REG_EXPAND_SZ", "REG_BINARY", "REG_QWORD").
- `str`: Value data (string for SZ types, decimal for DWORD/QWORD, hex for BINARY).

## Build

```text
cd bofs/remote/reg_set
cargo make
```

## Example

```text
beacon> reg_set <packed-arguments>
SUCCESS: Set <value> = '<value>' (<value>) on <value>\<value> (key <value>)
Invalid type: <value> (use REG_SZ, REG_DWORD, REG_EXPAND_SZ, REG_BINARY, REG_QWORD)
Invalid hive ID: <value> (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
