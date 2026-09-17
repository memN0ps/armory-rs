# sc_qtriggerinfo

Queries the trigger information for a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_TRIGGER_INFO (value 8). Displays the number of triggers and the type and action of each trigger.

## MITRE ATT&CK

- T1007 - System Service Discovery

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Service name.

## Build

```text
cd bofs/sa/sc_qtriggerinfo
cargo make
```

## Example

```text
beacon> sc_qtriggerinfo <packed-arguments>
TRIGGER[<value>]            : Type=<value> (<value>), Action=<value> (<value>), DataItems=<value>
SERVICE_NAME: <value>
<value> : <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
