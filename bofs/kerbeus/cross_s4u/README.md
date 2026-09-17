# cross_s4u

Performs the referral TGT, S4U2Self, and S4U2Proxy request chain for cross-domain constrained delegation across an existing domain trust.

## MITRE ATT&CK

- T1550.003 - Use Alternate Authentication Material: Pass the Ticket

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/service:SPN` - Target service principal name (required)
- `/targetdomain:DOMAIN` - Target domain for cross-realm (required)
- `/targetdc:DC` - Target domain controller (required)
- `/impersonateuser:USER` - User to impersonate (required)
- `/dc:DC` - Source domain controller
- `/ptt` - Print a reminder to pass the result to the separate `ptt` BOF

## Build

```text
cd bofs/kerbeus/cross_s4u
cargo make
```

## Example

```text
beacon> cross_s4u <packed-arguments>
[+] Cross-domain S4U2Proxy request successful
[*] Requesting foreign S4U2Self referral for <value>
[*] Requesting foreign S4U2Proxy service ticket
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
