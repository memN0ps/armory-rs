# asktgt

Requests a Kerberos TGT via raw AS-REQ with pre-authentication. Supports password, RC4 hash, or AES256 hash. Builds the encrypted timestamp PA-DATA using CDLocateCSystem, sends to KDC port 88, parses AS-REP, and outputs a base64-encoded .kirbi.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/user:USER` - Username (required)
- `/password:PASSWORD` - Plaintext password
- `/rc4:HASH` - RC4-HMAC (NTLM) hash
- `/aes256:HASH` - AES256 hash
- `/domain:DOMAIN` - Target domain (auto-detected if omitted)
- `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)
- `/enctype:rc4|aes256` - Encryption type (default: rc4)
- `/ptt` - Import ticket into current session
- `/nopac` - Request ticket without PAC

## Build

```text
cd bofs/kerbeus/asktgt
cargo make
```

## Example

```text
beacon> asktgt <packed-arguments>
[+] Ticket successfully imported.
[+] TGT request successful!
KDC_ERR_C_PRINCIPAL_UNKNOWN - client not found
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
