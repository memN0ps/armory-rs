# netuse

Maps or disconnects network drive connections using WNetAddConnection2A and WNetCancelConnection2A.

## MITRE ATT&CK

- T1021.002 - Remote Services: SMB/Windows Admin Shares

## Arguments

- `str`: Share path (e.g., `\\server\share`).
- `str`: Username (empty for current user).
- `str`: Password (empty if using current creds).
- `short`: Action (0 = connect, 1 = disconnect).

## Build

```text
cd bofs/sa/netuse
cargo make
```

## Example

```text
beacon> netuse <packed-arguments>
SUCCESS: Disconnected from <value>
SUCCESS: Connected to <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
