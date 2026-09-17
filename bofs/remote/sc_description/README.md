# sc_description

Sets a service's description on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfig2A` with `SERVICE_CONFIG_DESCRIPTION`.

## MITRE ATT&CK

- T1543.003 - Create or Modify System Process: Windows Service

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name.
- `str`: New description for the service.

## Build

```text
cd bofs/remote/sc_description
cargo make
```

## Example

```text
beacon> sc_description <packed-arguments>
SUCCESS.
set_service_description:
hostname:    <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
