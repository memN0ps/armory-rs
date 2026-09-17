# cacls

Displays file or directory DACL permissions by resolving each ACE to an account name and printing the associated access rights.

## MITRE ATT&CK

- T1222 - File and Directory Permissions Modification

## Arguments

- `str`: File or directory path to query.

## Build

```text
cd bofs/sa/cacls
cargo make
```

## Example

```text
beacon> cacls <packed-arguments>
No DACL found for <value>
Permissions for: <value>
<value> <value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
