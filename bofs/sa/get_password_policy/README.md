# get_password_policy

Retrieves the domain password policy and account lockout settings using NetUserModalsGet. Queries level 0 for password requirements and level 3 for lockout configuration.

## MITRE ATT&CK

- T1201 - Password Policy Discovery

## Arguments

- `wstr`: server - target server (empty for local)

## Build

```text
cd bofs/sa/get_password_policy
cargo make
```

## Example

```text
beacon> get_password_policy <packed-arguments>
Maximum password age:     Never expires
Force logoff:             <value> minutes
Lockout duration:         <value> minutes
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
