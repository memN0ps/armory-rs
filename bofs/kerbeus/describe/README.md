# describe

Parses and displays detailed information about a base64-encoded .kirbi ticket (KRB-CRED) using a built-in ASN.1 BER decoder. Shows service name, realm, client name, timestamps, flags, and encryption type.

## MITRE ATT&CK

- T1558 - Steal or Forge Kerberos Tickets

## Arguments

- `/ticket:BASE64` - Base64-encoded .kirbi ticket (required)

## Build

```text
cd bofs/kerbeus/describe
cargo make
```

## Example

```text
beacon> describe <packed-arguments>
StartTime (UTC)          :  <value>/<value>/<value> <value>:<value>:<value>
EndTime (UTC)            :  <value>/<value>/<value> <value>:<value>:<value>
RenewTill (UTC)          :  <value>/<value>/<value> <value>:<value>:<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
