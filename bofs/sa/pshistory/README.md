# pshistory

Reads a bounded tail of the current user's PSReadLine console history. Output can contain credentials, tokens, or other sensitive command text.

## MITRE ATT&CK

- T1552.003 - Unsecured Credentials: Bash History

## Arguments

- None. Output is capped at the last 50 lines and 32 KiB.

## Build

```text
cd bofs/sa/pshistory
cargo make
```

## Example

```text
beacon> pshistory <packed-arguments>
No PSReadLine console history was found for the current user.
Warning: command history may contain sensitive values.
PowerShell PSReadLine history
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
