# ldapsearch

Performs LDAP searches against Active Directory using the Windows LDAP API. Supports custom filters, attribute selection, auto-detection of the domain controller via DsGetDcNameA, and automatic base DN discovery via rootDSE.

## MITRE ATT&CK

- T1087.002 - Account Discovery: Domain Account

## Arguments

- `str`: LDAP filter (e.g., `(objectClass=user)`)
- `str`: Attributes comma-separated (e.g., `sAMAccountName,distinguishedName`) or `*` for all
- `str`: Domain controller hostname (empty = auto-detect via DsGetDcNameA)
- `int`: Result limit (0 = unlimited)

## Build

```text
cd bofs/sa/ldapsearch
cargo make
```

## Example

```text
beacon> ldapsearch <packed-arguments>
Displayed <value> of <value> entries.
(result limit <value> reached)
Auto-detected DC: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
