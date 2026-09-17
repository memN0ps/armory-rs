# kerberoasting

Requests an SPN service ticket with a supplied TGT and prints the ticket ciphertext as a Hashcat-compatible Kerberoast hash.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/spn:SPN` - Target service principal name (required)
- `/user:NAME` - Optional service-account label for the Hashcat record
- `/domain:DOMAIN` - Request realm (defaults to the TGT realm)
- `/dc:DC` - Domain controller hostname or IP

## Build

```text
cd bofs/kerbeus/kerberoasting
cargo make
```

## Example

```text
beacon> kerberoasting <packed-arguments>
[+] Kerberoast complete:

<value>
[*] Requesting service ticket for: <value>
[*] Action: Kerberoasting
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
