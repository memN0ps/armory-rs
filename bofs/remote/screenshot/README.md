# screenshot

Captures the current virtual desktop through GDI and returns a 32-bit BMP through Beacon's file-transfer protocol. An optional output path supports standalone COFF loaders; the default mode does not create a temporary file.

## MITRE ATT&CK

- T1113 - Screen Capture

## Arguments

- Optional `str`: output path for standalone COFF loaders that do not implement Beacon's file-transfer protocol. With no argument, the BOF returns `screenshot.bmp` through the normal Beacon protocol.

## Build

```text
cd bofs/remote/screenshot
cargo make
```

## Example

```text
beacon> screenshot <packed-arguments>
[+] Screenshot captured: <value>x<value> | <value> bytes | screenshot.bmp
[+] Screenshot captured: <value>x<value> | <value> bytes | <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
