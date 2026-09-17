# shutdown

Shuts down or reboots a local or remote computer using `InitiateSystemShutdownExA`. Enables the appropriate shutdown privilege (`SeShutdownPrivilege` for local, `SeRemoteShutdownPrivilege` for remote) before initiating the shutdown.

## MITRE ATT&CK

- T1529 - System Shutdown/Reboot

## Arguments

- `str`: Target hostname (empty string for local machine).
- `int`: Timeout in seconds before shutdown.
- `int`: Force close applications (0 = no, 1 = yes).
- `int`: Reboot after shutdown (0 = no, 1 = yes).

## Build

```text
cd bofs/remote/shutdown
cargo make
```

## Example

```text
beacon> shutdown <packed-arguments>
SUCCESS.
Shutdown privilege enabled.
timeout:  <value> seconds
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
