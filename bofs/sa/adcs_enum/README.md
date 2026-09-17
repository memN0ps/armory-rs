# adcs_enum

Enumerates Active Directory Certificate Services (AD CS) Certificate Authorities and certificate templates by dynamically loading certcli.dll and calling the CA enumeration APIs (CAEnumFirstCA, CAEnumCertTypesForCA, etc.).

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

- `scope` (optional, wide string) - Domain/forest scope for CA enumeration. If empty or omitted, uses the default domain.

## Build

```text
cd bofs/sa/adcs_enum
cargo make
```

## Example

```text
beacon> adcs_enum <packed-arguments>
=== ADCS enumeration complete ===
=== ADCS Enumeration (T1649) ===
No Certificate Authorities found in the domain.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
