# netloggedon2

Lists logged-on users with JSON output for BOFHound ingestion. Same functionality as netloggedon but outputs structured JSON.

## MITRE ATT&CK

- T1033 - System Owner/User Discovery

## Arguments

- `str`: Hostname (empty for localhost).

## Build

```text
cd bofs/sa/netloggedon2
cargo make
```

## Example

```text
beacon> netloggedon2 <packed-arguments>
{"username":"<value>","domain":"<value>","logon_server":"<value>"}}
{"host":"<value>","users":[
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
