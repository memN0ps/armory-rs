# schtasksdelete

Deletes a scheduled task on a local or remote host by invoking `schtasks /delete /tn <name> /f` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1053.005 - Scheduled Task/Job: Scheduled Task

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Task name to delete.

## Build

```text
cd bofs/remote/schtasksdelete
cargo make
```

## Example

```text
beacon> schtasksdelete <packed-arguments>
schtasksdelete:
hostname: <value>
taskname: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
