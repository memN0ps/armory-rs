# clipboardgrab

Reads a bounded Unicode-text snapshot from the current interactive clipboard. Output can contain credentials or other sensitive values.

## MITRE ATT&CK

- T1115 - Clipboard Data

## Arguments

- None. Output is capped at 8192 UTF-16 code units.

## Build

```text
cd bofs/sa/clipboardgrab
cargo make
```

## Example

```text
beacon> clipboardgrab <packed-arguments>
Warning: clipboard output may contain sensitive values.
Clipboard output limit reached.
<empty Unicode clipboard text>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
