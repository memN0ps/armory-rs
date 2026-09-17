# ldapsecuritycheck

Checks LDAP signing and channel binding requirements on a domain controller. Attempts unauthenticated simple binds to determine if LDAP signing is enforced, and tests LDAPS (port 636) connectivity for channel binding assessment.

## MITRE ATT&CK

- T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning

## Arguments

- `str`: Domain controller hostname (empty = auto-detect via DsGetDcNameA)

## Build

```text
cd bofs/sa/ldapsecuritycheck
cargo make
```

## Example

```text
beacon> ldapsecuritycheck <packed-arguments>
=== LDAP Security Check Complete ===
[+] LDAPS connection succeeded - SSL/TLS is available.
[*] Testing authenticated LDAP bind (NEGOTIATE)...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
