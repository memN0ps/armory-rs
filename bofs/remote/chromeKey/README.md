# chromeKey

Decrypts Chrome's encryption key using CryptUnprotectData (DPAPI). Takes a base64-encoded encrypted key from Chrome's Local State file, strips the "DPAPI" prefix, and decrypts it.

## MITRE ATT&CK

- T1555.003 - Credentials from Web Browsers

## Arguments

- `str`: Base64-encoded encrypted key from Chrome's Local State.

## Build

```text
cd bofs/remote/chromeKey
cargo make
```

## Example

```text
beacon> chromeKey <packed-arguments>
SUCCESS.
chromeKey: Decrypting Chrome encryption key via DPAPI
Key does not have expected DPAPI prefix
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
