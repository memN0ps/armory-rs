# sc_config

Modifies a Windows service's configuration on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfigA`.

## MITRE ATT&CK

- T1543.003 - Create or Modify System Process: Windows Service

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name.
- `str`: Binary path (empty string to leave unchanged).
- `int`: Start type (pass 0xFFFFFFFF / SERVICE_NO_CHANGE to leave unchanged).
- `int`: Error control (pass 0xFFFFFFFF / SERVICE_NO_CHANGE to leave unchanged).

## Build

```text
cd bofs/remote/sc_config
cargo make
```

## Example

```text
beacon> sc_config <packed-arguments>
SUCCESS.
starttype:    <value>
errorcontrol: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
