# adcs_request_on_behalf

Requests a certificate on behalf of another user via an enrollment agent certificate by invoking `certreq` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1649 - Steal or Forge Authentication Certificates

## Arguments

- `str`: CA config string (e.g., `ca01.domain.local\Domain-CA`).
- `str`: Template name (e.g., `User`).
- `str`: On-behalf-of user (e.g., `DOMAIN\administrator`).
- `str`: Path to certificate request file (.req / .csr).

## Build

```text
cd bofs/remote/adcs_request_on_behalf
cargo make
```

## Example

```text
beacon> adcs_request_on_behalf <packed-arguments>
=== ADCS on-behalf-of request complete ===
=== ADCS Certificate Request On Behalf (T1649) ===
CA Config:    <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
