# sc_qdescription

Queries the description of a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_DESCRIPTION.

## MITRE ATT&CK

- T1007 - System Service Discovery

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Service name.

## Build

```text
cd bofs/sa/sc_qdescription
cargo make
```

## Example

```text
beacon> sc_qdescription <packed-arguments>
DESCRIPTION: (none)
SERVICE_NAME: <value>
DESCRIPTION: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
