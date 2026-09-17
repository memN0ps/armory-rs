# changepw

Changes a user password via the MS kpasswd protocol (port 464). First requests a kadmin/changepw service ticket via TGS-REQ, then sends a KRB-PRIV message with the new password.

## MITRE ATT&CK

- T1098 - Account Manipulation

## Arguments

- `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
- `/new:PASSWORD` - New password (required)
- `/targetuser:USER` - Target user (optional, requires `/targetdomain`)
- `/targetdomain:DOMAIN` - Target domain (optional, requires `/targetuser`)
- `/dc:DC` - Domain controller hostname or IP

## Build

```text
cd bofs/kerbeus/changepw
cargo make
```

## Example

```text
beacon> changepw <packed-arguments>
[+] Password change successful
[*] Sending authenticated password request to <value>:464
[*] Requesting kadmin/changepw service ticket
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
