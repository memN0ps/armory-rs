# unexpireuser

Sets a user account password to never expire by setting the UF_DONT_EXPIRE_PASSWD flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008).

## MITRE ATT&CK

- T1098 - Account Manipulation

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Username whose password should never expire.

## Build

```text
cd bofs/remote/unexpireuser
cargo make
```

## Example

```text
beacon> unexpireuser <packed-arguments>
SUCCESS: Password for '<value>' set to never expire.
Setting password to never expire for user '<value>' on '<value>'...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
