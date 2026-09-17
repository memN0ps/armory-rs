# get_netsession2

Enumerates network sessions with JSON output for BOFHound ingestion.

## MITRE ATT&CK

- T1049 - System Network Connections Discovery

## Arguments

- `str`: Hostname (empty for localhost).

## Build

```text
cd bofs/sa/get_netsession2
cargo make
```

## Example

```text
beacon> get_netsession2 <packed-arguments>
{"client":"<value>","user":"<value>","time":<value>,"idle":<value>}}
{"host":"<value>","sessions":[
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
