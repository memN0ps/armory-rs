# dir

Lists directory contents with file sizes and timestamps.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

- `str`: Directory path to list.

## Build

```text
cd bofs/sa/dir
cargo make
```

## Example

```text
beacon> dir <packed-arguments>
<value>/<value>/<value> <value>:<value><value> <value>
<value> Total File Size for <value> File(s)
Couldn't open <value>: Error <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
