# probe

Checks if a TCP port is open on a target host by attempting a non-blocking connect with a configurable timeout.

## MITRE ATT&CK

- T1046 - Network Service Discovery

## Arguments

- `host` (str) - Target IP address (e.g. "10.0.0.1").
- `port` (int) - TCP port number to probe.
- `timeout` (int) - Connection timeout in milliseconds.

## Build

```text
cd bofs/sa/probe
cargo make
```

## Example

```text
beacon> probe <packed-arguments>
Probing <value>:<value> (timeout <value>ms)...
<value>:<value> is CLOSED (timeout)
Invalid IP address: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
