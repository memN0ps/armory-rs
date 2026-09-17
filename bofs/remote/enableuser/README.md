# enableuser

Enables a user account by clearing the UF_ACCOUNTDISABLE flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008).

## MITRE ATT&CK

- T1098 - Account Manipulation

## Arguments

- `str`: Hostname (empty for localhost).
- `str`: Username to enable.

## Build

```text
cd bofs/remote/enableuser
cargo make
```

## Example

```text
beacon> enableuser <packed-arguments>
SUCCESS: User '<value>' enabled.
Enabling user '<value>' on '<value>'...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
