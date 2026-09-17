# sc_failure

Sets service failure recovery actions on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfig2A` with `SERVICE_CONFIG_FAILURE_ACTIONS`.

## MITRE ATT&CK

- T1543.003 - Create or Modify System Process: Windows Service

## Arguments

- `str`: Target hostname (empty string for local machine).
- `str`: Service name.
- `int`: Reset period in seconds.
- `int`: Action 1 type (0=NONE, 1=RESTART, 2=REBOOT, 3=RUN_COMMAND).
- `int`: Delay 1 in milliseconds.
- `int`: Action 2 type (0=NONE, 1=RESTART, 2=REBOOT, 3=RUN_COMMAND).
- `int`: Delay 2 in milliseconds.

## Build

```text
cd bofs/remote/sc_failure
cargo make
```

## Example

```text
beacon> sc_failure <packed-arguments>
SUCCESS.
action1:      type=<value> delay=<value>ms
action2:      type=<value> delay=<value>ms
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
