# make_token_cert

Imports a PFX certificate file and displays certificate information including the subject name, issuer, serial number, and thumbprint (SHA1). This can be used to verify PFX files for certificate-based authentication.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

- `bin`: PFX file data (raw bytes)
- `str`: PFX password

## Build

```text
cd bofs/remote/make_token_cert
cargo make
```

## Example

```text
beacon> make_token_cert <packed-arguments>
[+] PFX imported successfully.
=== PFX Import Complete ===
No certificates found in the PFX.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
