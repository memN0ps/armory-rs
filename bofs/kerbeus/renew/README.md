# renew

Renews an existing Kerberos TGT via TGS-REQ with the RENEW flag set. Uses the same AP-REQ construction as asktgs targeting krbtgt.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)
- `/ptt` - Import renewed ticket into current session

## Build

```text
cd bofs/kerbeus/renew
cargo make
```

## Example

```text
beacon> renew <packed-arguments>
[+] TGT renewal successful!
[*] /ptt: use the ptt BOF to import this ticket
[*] base64(ticket.kirbi):

<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
