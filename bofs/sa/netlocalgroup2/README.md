# netlocalgroup2

Enumerates local groups with JSON output for BOFHound ingestion.

## MITRE ATT&CK

- T1069.001 - Permission Groups Discovery: Local Groups

## Arguments

- `str`: Hostname (empty for localhost).

## Build

```text
cd bofs/sa/netlocalgroup2
cargo make
```

## Example

```text
beacon> netlocalgroup2 <packed-arguments>
{"name":"<value>","comment":"<value>"}}
{"host":"<value>","groups":[
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
