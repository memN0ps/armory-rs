# netlocalgroup

Enumerates local groups on a system and optionally lists members of a specific local group using the NetLocalGroupEnum and NetLocalGroupGetMembers Windows API functions.

## MITRE ATT&CK

- T1069.001 - Permission Groups Discovery: Local Groups

## Arguments

- `short`: `0` to list groups or `1` to list members.
- `str`: Optional remote computer name; use an empty string for local.
- `str`: Group name when listing members.

## Build

```text
cd bofs/sa/netlocalgroup
cargo make
```

## Example

```text
beacon> netlocalgroup <packed-arguments>
Error: invalid type <value>. Use 0 for groups, 1 for members.
Total members: <value>
Total groups: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
