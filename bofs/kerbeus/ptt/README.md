# ptt

Pass-the-ticket - imports a base64-encoded .kirbi ticket into the current logon session via LsaCallAuthenticationPackage with KerbSubmitTicketMessage.

## MITRE ATT&CK

- T1550.003 - Use Alternate Authentication Material: Pass the Ticket

## Arguments

- `/ticket:BASE64` - Base64-encoded .kirbi ticket (required)
- `/luid:LUID` - Target logon session LUID (optional, requires SYSTEM)

## Build

```text
cd bofs/kerbeus/ptt
cargo make
```

## Example

```text
beacon> ptt <packed-arguments>
[+] Ticket successfully imported.
[*] Action: Import Ticket
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
