# cve_2022_26923

Creates, inspects, or removes a machine account in the default Computers container through an authenticated and sealed LDAP session. The create action sets the supplied domain controller name as `dNSHostName`, which is the directory primitive used by CVE-2022-26923 before certificate enrollment. Every mutation is verified and removal is a separate explicit action.

## MITRE ATT&CK

- T1136.002 - Create Account: Domain Account
- T1649 - Steal or Forge Authentication Certificates

## Arguments

- `str`: `query`, `create`, or `delete`.
- `str`: Domain controller hostname or address.
- `str`: Machine name without the trailing `$`.
- `str`: Password for `create`; pass an empty string otherwise.
- `str`: Spoofed domain controller FQDN for `create`; pass an empty string otherwise.

## Build

```text
cd bofs/remote/cve_2022_26923
cargo make
```

## Example

```text
beacon> cve_2022_26923 <packed-arguments>
Machine account <value> created and verified with dNSHostName=<value>. Certificate enrollment is a separate action; delete this account after use.
Machine name must be 1-15 letters, digits, hyphens, or underscores without a trailing $.
Create requires a non-empty password and a valid spoofed domain controller FQDN.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
