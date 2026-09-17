# adcs_request

Enumerates available certificate templates from Active Directory Certificate Services (AD CS) by invoking `certutil -template` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

- `str`: CA config string (e.g., `ca01.domain.local\Domain-CA`). If empty, queries the local default CA.
- `str`: Template name filter (e.g., `User`). If empty, lists all templates.

## Build

```text
cd bofs/remote/adcs_request
cargo make
```

## Example

```text
beacon> adcs_request <packed-arguments>
=== ADCS Certificate Template Enumeration (T1649) ===
=== ADCS template enumeration complete ===
certutil -config "<value>" -template "<value>"
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
