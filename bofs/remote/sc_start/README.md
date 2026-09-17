# sc_start

Starts a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and issuing a start command via `StartServiceA`.

## MITRE ATT&CK

- T1569.002 - System Services: Service Execution

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name to start.

## Build

```text
cd bofs/remote/sc_start
cargo make
```

## Example

```text
beacon> sc_start <packed-arguments>
SUCCESS.
hostname:    <value>
servicename: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
