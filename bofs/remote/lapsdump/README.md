# lapsdump

Queries one computer object for legacy Microsoft LAPS and Windows LAPS attributes using the current security context. Encrypted Windows LAPS data is reported as a bounded hexadecimal preview rather than decrypted.

## MITRE ATT&CK

- T1555.005 - Credentials from Password Stores: Password Managers
- T1087.002 - Account Discovery: Domain Account

## Arguments

- `str`: Computer name or DNS hostname.
- `str`: Domain controller hostname, empty for automatic discovery.

## Build

```text
cd bofs/remote/lapsdump
cargo make
```

## Example

```text
beacon> lapsdump <packed-arguments>
[+] LAPS attributes for <value>
[+] <value>: <value>... (<value> bytes)
[+] <value>: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
