# purge

Purges all cached Kerberos tickets from the current logon session via LsaCallAuthenticationPackage with KerbPurgeTicketCacheMessage.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/luid:LUID` - Target logon session LUID (optional, requires SYSTEM)

## Build

```text
cd bofs/kerbeus/purge
cargo make
```

## Example

```text
beacon> purge <packed-arguments>
[+] Successfully purged tickets.
[*] Action: Purge Tickets
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
