# locale

Reports the system locale, language, country, and localized date format.

## MITRE ATT&CK

- T1614 - System Location Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/locale
cargo make
```

## Example

```text
beacon> inline-execute /path/to/locale.x64.o
Error retrieving system locale
Error retrieving language
Locale: <value> (<value>)
```
