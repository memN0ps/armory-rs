# triage

Displays a compact table of cached Kerberos tickets showing LUID, client, service, and expiration time.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/luid:LUID` - Target logon session LUID (optional, requires SYSTEM)
- `/user:USER` - Filter by username (optional, requires SYSTEM)
- `/service:SPN` - Filter by service name (optional)
- `/client:CLIENT` - Filter by client name (optional)

## Build

```text
cd bofs/kerbeus/triage
cargo make
```

## Example

```text
beacon> triage <packed-arguments>
--------------------------------------------------------------------------------------------------------------------------
Action: List Kerberos Tickets (Current User)
Action: List Kerberos Tickets (All Users)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
