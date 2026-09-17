# nonpagedldapsearch

Performs a simple (non-paged) LDAP search against Active Directory using ldap_search_sA directly. This is a simplified version of ldapsearch that does not use paged result controls.

## MITRE ATT&CK

- T1087.002 - Account Discovery: Domain Account

## Arguments

- `str`: LDAP filter (e.g., `(objectClass=user)`)
- `str`: Attributes comma-separated (e.g., `sAMAccountName,distinguishedName`) or `*` for all
- `str`: Domain controller hostname (empty = auto-detect via DsGetDcNameA)
- `int`: Result limit (0 = unlimited)

## Build

```text
cd bofs/sa/nonpagedldapsearch
cargo make
```

## Example

```text
beacon> nonpagedldapsearch <packed-arguments>
Displayed <value> of <value> entries.
(result limit <value> reached)
Auto-detected DC: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
