# sc_create

Creates a new Windows service on a local or remote host by connecting to the Service Control Manager (SCM) and calling `CreateServiceA`.

## MITRE ATT&CK

- T1543.003 - Create or Modify System Process: Windows Service

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name.
- `str`: Display name.
- `str`: Binary path for the service executable.

## Build

```text
cd bofs/remote/sc_create
cargo make
```

## Example

```text
beacon> sc_create <packed-arguments>
SUCCESS.
create_service:
hostname:    <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
