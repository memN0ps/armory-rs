# sha256

Computes the SHA-256 hash of a file.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

- `str`: File path to hash.

## Build

```text
cd bofs/sa/sha256
cargo make
```

## Example

```text
beacon> sha256 <packed-arguments>
Error: Could not initialize HCRYPTPROV context
Error: Could not find file "<value>"
SHA-256 Hash for <value>: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
