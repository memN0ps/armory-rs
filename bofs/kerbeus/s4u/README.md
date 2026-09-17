# s4u

Performs S4U2Self and S4U2Proxy constrained delegation abuse via TGS-REQ with PA-FOR-USER PA-DATA for impersonation.

## MITRE ATT&CK

- T1550.003 - Use Alternate Authentication Material: Pass the Ticket

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/service:SPN` - Target service principal name (required unless `/self`)
- `/impersonateuser:USER` - User to impersonate via S4U2Self
- `/tgs:BASE64` - Existing S4U2Self ticket for S4U2Proxy
- `/dc:DC` - Domain controller hostname or IP
- `/ptt` - Print a reminder to pass the result to the separate `ptt` BOF
- `/self` - Return the S4U2Self ticket without an S4U2Proxy request

## Build

```text
cd bofs/kerbeus/s4u
cargo make
```

## Example

```text
beacon> s4u <packed-arguments>
[+] S4U2Proxy request successful
[+] S4U2Self request successful
[*] Import the ticket with the ptt BOF
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
