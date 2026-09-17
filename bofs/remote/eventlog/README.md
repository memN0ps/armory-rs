# eventlog

Inspects Windows Event Log channels and manages one exact classic custom log through an ownership-checked create, write, clear, and destroy cycle. Arbitrary channel clearing requires an explicit absolute backup path.

## MITRE ATT&CK

- T1070.001 - Indicator Removal: Clear Windows Event Logs
- T1562.002 - Impair Defenses: Disable Windows Event Logging

## Arguments

- `str`: `inspect`, `sources`, `create`, `write`, `clear`, or `destroy`.
- `str`: Channel or classic log name.
- Optional `str`: Source name; pass an empty string when clearing.
- Optional `str`: Event text or absolute backup path.

## Build

```text
cd bofs/remote/eventlog
cargo make
```

## Example

```text
beacon> eventlog <packed-arguments>
Removed owned event-log registration | log=<value> | source=<value>
Wrote classic event | log=<value> | source=<value> | utf8-bytes=<value>
Created classic event log | log=<value> | source=<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
