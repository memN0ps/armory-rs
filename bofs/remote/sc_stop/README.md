# sc_stop

Stops a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, querying its current state, and issuing a stop command via `ControlService`.

## MITRE ATT&CK

- T1569.002 - System Services: Service Execution

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name to stop.

## Build

```text
cd bofs/remote/sc_stop
cargo make
```

## Example

```text
beacon> sc_stop <packed-arguments>
SUCCESS.
Service is already stopped.
Service stop pending...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
