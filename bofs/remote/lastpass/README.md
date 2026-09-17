# lastpass

Scans browser process memory for LastPass vault data by searching for known patterns such as "lastpass" vault markers and encrypted vault content indicators. Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory.

## MITRE ATT&CK

- T1555.005 - Credentials from Password Stores: Password Managers

## Arguments

- `int`: Target browser process ID (0 to auto-detect is not supported; provide a specific PID).

## Build

```text
cd bofs/remote/lastpass
cargo make
```

## Example

```text
beacon> lastpass <packed-arguments>
SUCCESS.
lastpass: Scanning process <value> for LastPass vault data
Scanned <value> regions, found <value> LastPass artifact(s)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
