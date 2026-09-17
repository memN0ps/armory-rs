# reg_query

Queries the Windows registry for a specific value or enumerates values and subkeys under a given registry path. Supports remote registry access via RegConnectRegistryA when a hostname is provided.

## MITRE ATT&CK

- T1012 - Query Registry

## Arguments

- `str`: Hostname (empty for localhost).
- `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
- `str`: Registry path (subkey).
- `str`: Key/value name (empty to enumerate).
- `int`: Recursive flag (unused in initial port, reserved).

## Build

```text
cd bofs/sa/reg_query
cargo make
```

## Example

```text
beacon> reg_query <packed-arguments>
Invalid hive ID: <value> (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)
<value> (<value>) : (invalid size)
<value> (<value>) : 0x<value> (<value>)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
