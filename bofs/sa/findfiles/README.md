# findfiles

Searches a directory tree for a case-insensitive wildcard pattern. The maximum depth and result count are mandatory bounds, and reparse points are never traversed.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

- `str`: Root directory.
- `str`: File-name pattern using `*` and `?`.
- `int`: Maximum directory depth, from 0 through 32.
- `int`: Maximum results, from 1 through 1000.

## Build

```text
cd bofs/sa/findfiles
cargo make
```

## Example

```text
beacon> findfiles <packed-arguments>
Matches: <value> | directories searched: <value> | inaccessible/error: <value><value>
Searching <value> for <value> (depth <value>, limit <value>)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
