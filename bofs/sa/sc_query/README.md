# sc_query

Queries the status of a specific Windows service or enumerates all services. Displays service type, state, PID, exit codes, and flags.

## MITRE ATT&CK

- T1007 - System Service Discovery

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Service name (empty to enumerate all services).

## Build

```text
cd bofs/sa/sc_query
cargo make
```

## Example

```text
beacon> sc_query <packed-arguments>
<value> <value> <value> <value> PID:<value>
Total services: <value>
SERVICE_NAME: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
