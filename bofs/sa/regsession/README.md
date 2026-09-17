# regsession

Enumerates logged-on user SIDs by inspecting subkeys under HKEY_USERS in the Windows registry. Filters for interactive user SIDs (S-1-5-21-*) and excludes class subkeys (those containing an underscore). Supports remote registry access via `RegConnectRegistryA` when a hostname is provided.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery

## Arguments

- `str`: Hostname (empty for localhost).

## Build

```text
cd bofs/sa/regsession
cargo make
```

## Example

```text
beacon> regsession <packed-arguments>
Enumerating logged-on user SIDs from HKEY_USERS on <value>
Total logged-on user SIDs: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
