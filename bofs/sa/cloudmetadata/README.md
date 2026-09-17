# cloudmetadata

Performs one bounded request against a fixed link-local metadata endpoint. The provider must be selected explicitly. This command does not request AWS IMDSv2 tokens, managed-identity tokens, service-account tokens, or recursive metadata values.

## MITRE ATT&CK

- T1580 - Cloud Infrastructure Discovery

## Arguments

- `str`: Provider: `azure`, `aws`, or `gcp`.

## Build

```text
cd bofs/sa/cloudmetadata
cargo make
```

## Example

```text
beacon> cloudmetadata <packed-arguments>
HTTP status: <value>
Fixed link-local endpoint | timeout: 2000 ms | response cap: 16384 bytes
Credential and identity-token endpoints are not requested.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
