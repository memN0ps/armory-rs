# wallpaper

Enumerates the current wallpaper path for each desktop monitor through the documented IDesktopWallpaper COM interface. It does not read image files.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/wallpaper
cargo make
```

## Example

```text
beacon> inline-execute /path/to/wallpaper.x64.o
Desktop wallpaper inventory
[<value>] <value> | wallpaper unavailable: 0x<value>
[<value>] monitor path unavailable: 0x<value>
```
