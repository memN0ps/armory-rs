# machineaccount

Queries, creates, or deletes one exact Active Directory machine account on a named domain controller through NetAPI. Creation refuses to overwrite an existing account. Deletion is a separate explicit rollback action.

## MITRE ATT&CK

- T1136.002 - Create Account: Domain Account

## Arguments

- `str`: `query`, `add`, or `delete`.
- `str`: Domain controller name, normally prefixed with `\\`.
- `str`: Machine account name ending in `$`.
- `str`: Password for `add`; pass an empty string for `query` and `delete`.

## Build

```text
cd bofs/remote/machineaccount
cargo make
```

## Example

```text
beacon> machineaccount <packed-arguments>
Machine account <value> created and verified. Run the matching delete action to roll it back.
Machine account <value> exists | workstation-trust=<value> | flags=0x<value>
Machine account must be 2-20 characters and end in $.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
