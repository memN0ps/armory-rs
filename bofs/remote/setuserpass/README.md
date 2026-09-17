# setuserpass

Changes a user's password using NetUserSetInfo at level 1003.

## MITRE ATT&CK

- T1098 - Account Manipulation

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Username whose password to change.
- `str`: New password.

## Build

```text
cd bofs/remote/setuserpass
cargo make
```

## Example

```text
beacon> setuserpass <packed-arguments>
SUCCESS: Password changed for user '<value>'.
Setting password for user '<value>' on '<value>'...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
