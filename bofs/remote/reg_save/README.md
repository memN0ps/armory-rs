# reg_save

Saves a registry hive to a file using RegSaveKeyA. Automatically enables SeBackupPrivilege which is required for this operation. Useful for dumping SAM, SECURITY, or SYSTEM hives for offline credential extraction.

## MITRE ATT&CK

- T1003.002 - OS Credential Dumping: Security Account Manager

## Arguments

- `str`: Hive name ("HKLM", "HKCU", "HKCR", "HKU", "SAM", "SYSTEM", "SECURITY").
- `str`: Output file path.

## Build

```text
cd bofs/remote/reg_save
cargo make
```

## Example

```text
beacon> reg_save <packed-arguments>
SUCCESS: Saved <value> hive to '<value>'
Invalid hive: <value> (use HKLM, HKCU, HKCR, HKU, SAM, SYSTEM, SECURITY)
Enabled SeBackupPrivilege
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
