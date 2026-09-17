# reg_delete

Deletes a registry value or key. If a value name is provided, deletes just that value using RegDeleteValueA. If the value name is empty, deletes the entire key using RegDeleteKeyA. Supports remote registry access via RegConnectRegistryA when a hostname is provided.

## MITRE ATT&CK

- T1112 - Modify Registry

## Arguments

- `str`: Hostname (empty for localhost).
- `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
- `str`: Registry path (subkey).
- `str`: Value name (empty to delete the entire key).

## Build

```text
cd bofs/remote/reg_delete
cargo make
```

## Example

```text
beacon> reg_delete <packed-arguments>
SUCCESS: Deleted value '<value>' from <value>\<value>
SUCCESS: Deleted key <value>\<value>
Invalid hive ID: <value> (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
