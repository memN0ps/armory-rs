# hash

Generates Kerberos password hashes (RC4-HMAC, AES128, AES256) from a plaintext password using CDLocateCSystem from cryptdll.dll. AES salts are derived from the domain and username.

## MITRE ATT&CK

- T1558 - Steal or Forge Kerberos Tickets

## Arguments

- `/password:PASSWORD` - Plaintext password (required)
- `/user:USER` - Username for AES salt (optional)
- `/domain:DOMAIN` - Domain for AES salt (optional)

## Build

```text
cd bofs/kerbeus/hash
cargo make
```

## Example

```text
beacon> hash <packed-arguments>
[*] Action: Calculate Password Hash(es)
[*] Input Password           : <value>
[*] Input Username           : <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
