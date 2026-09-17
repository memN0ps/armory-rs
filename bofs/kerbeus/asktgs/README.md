# asktgs

Requests a Kerberos service ticket via raw TGS-REQ using an existing TGT. Builds an AP-REQ with encrypted authenticator, sends to KDC port 88, parses TGS-REP, and outputs a base64-encoded .kirbi.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/service:SPN` - Target service principal name (required)
- `/domain:DOMAIN` - Target domain (auto-detected if omitted)
- `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)
- `/ptt` - Import ticket into current session

## Build

```text
cd bofs/kerbeus/asktgs
cargo make
```

## Example

```text
beacon> asktgs <packed-arguments>
[+] TGS request successful!
[*] /ptt: use the ptt BOF to import this ticket
[*] Requesting service ticket for: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
