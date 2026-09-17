# schtasksenum

Enumerates all scheduled tasks on a local or remote host by invoking `schtasks /query /fo list` via `CreateProcessA` and capturing the output through an anonymous pipe.

## MITRE ATT&CK

- T1053.005 - Scheduled Task/Job: Scheduled Task

## Arguments

- `str`: Target hostname (empty string for local machine).

## Build

```text
cd bofs/sa/schtasksenum
cargo make
```

## Example

```text
beacon> schtasksenum <packed-arguments>
schtasksenum:
hostname: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
