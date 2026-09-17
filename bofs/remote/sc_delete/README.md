# sc_delete

Deletes a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `DeleteService`.

## MITRE ATT&CK

- T1489 - Service Stop

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name to delete.

## Build

```text
cd bofs/remote/sc_delete
cargo make
```

## Example

```text
beacon> sc_delete <packed-arguments>
SUCCESS.
delete_service:
hostname:    <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
