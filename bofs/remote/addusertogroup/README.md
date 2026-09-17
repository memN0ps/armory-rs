# addusertogroup

Adds a user to a local group using NetLocalGroupAddMembers.

## MITRE ATT&CK

- T1098 - Account Manipulation

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Username to add.
- `str`: Group name to add user to.

## Build

```text
cd bofs/remote/addusertogroup
cargo make
```

## Example

```text
beacon> addusertogroup <packed-arguments>
SUCCESS: User '<value>' added to group '<value>'.
Adding user '<value>' to group '<value>' on '<value>'...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
