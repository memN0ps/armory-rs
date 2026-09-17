# ghost_task

Creates a "ghost" scheduled task by writing directly to the Task Scheduler registry keys, bypassing the Task Scheduler COM API for stealth. Writes a registry key under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<taskname>` with the command stored as a string value.

## MITRE ATT&CK

- T1053.005 - Scheduled Task/Job: Scheduled Task

## Arguments

- `str`: Task name.
- `str`: Command to execute.

## Build

```text
cd bofs/remote/ghost_task
cargo make
```

## Example

```text
beacon> ghost_task <packed-arguments>
Ghost task created (new key):
Path:    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<value>
Note: This creates registry markers only. Full task execution requires
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
