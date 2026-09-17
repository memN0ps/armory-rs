# disableuser

Disables a user account by setting the UF_ACCOUNTDISABLE flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008).

## MITRE ATT&CK

- T1531 - Account Access Removal

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Username to disable.

## Build

```text
cd bofs/remote/disableuser
cargo make
```

## Example

```text
beacon> disableuser <packed-arguments>
SUCCESS: User '<value>' disabled.
Disabling user '<value>' on '<value>'...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
