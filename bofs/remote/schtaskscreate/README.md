# schtaskscreate

Creates a scheduled task on a local or remote host by invoking `schtasks /create /tn <name> /tr <command> /sc once /st 00:00 /f` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1053.005 - Scheduled Task/Job: Scheduled Task

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Task name.
- `str`: Command to execute.

## Build

```text
cd bofs/remote/schtaskscreate
cargo make
```

## Example

```text
beacon> schtaskscreate <packed-arguments>
schtaskscreate:
hostname: <value>
taskname: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
