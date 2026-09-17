# netgroup

Lists domain groups and their members using NetQueryDisplayInformation and NetGroupGetUsers Windows API functions.

## MITRE ATT&CK

- T1069.002 - Permission Groups Discovery: Domain Groups

## Arguments

- `short`: type - 0 to list groups, 1 to list members of a specific group
- `wstr`: server - target server (empty for local)
- `wstr`: groupname - group name (required when type=1)

## Build

```text
cd bofs/sa/netgroup
cargo make
```

## Example

```text
beacon> netgroup <packed-arguments>
Error: invalid type <value>. Use 0 for groups, 1 for members.
<value> <value> <value> <value>
<value> <value> <value> 0x<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
