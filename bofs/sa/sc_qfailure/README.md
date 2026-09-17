# sc_qfailure

Queries the failure actions configured for a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_FAILURE_ACTIONS (value 2). Displays the reset period, reboot message, command, and each configured failure action with its type and delay.

## MITRE ATT&CK

- T1007 - System Service Discovery

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Service name.

## Build

```text
cd bofs/sa/sc_qfailure
cargo make
```

## Example

```text
beacon> sc_qfailure <packed-arguments>
ACTION[<value>]             : <value> (delay: <value> ms)
<value> : <value> seconds
SERVICE_NAME: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
