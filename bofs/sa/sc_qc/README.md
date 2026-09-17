# sc_qc

Queries the configuration of a specific Windows service using QueryServiceConfigA. Displays service type, start type, error control, binary path, load order group, tag, display name, dependencies, and service start name.

## MITRE ATT&CK

- T1007 - System Service Discovery

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Service name.

## Build

```text
cd bofs/sa/sc_qc
cargo make
```

## Example

```text
beacon> sc_qc <packed-arguments>
SERVICE_NAME: <value>
<value> : <value> <value>
<value> : <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
