# asreproasting

Requests an AS-REP for users with Kerberos pre-authentication disabled and outputs the encrypted part as a Hashcat-compatible hash for offline cracking. Supports RC4 and AES encryption types.

## MITRE ATT&CK

- T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

## Arguments

- `/user:USER` - Target username (required)
- `/domain:DOMAIN` - Target domain (auto-detected if omitted)
- `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)

## Build

```text
cd bofs/kerbeus/asreproasting
cargo make
```

## Example

```text
beacon> asreproasting <packed-arguments>
[*] Building AS-REQ (w/o preauth) for: '<value>\<value>'
[*] Action: AS-REP Roasting
[+] AS-REP hash:

<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
