# enum_filter_driver

Enumerates minifilter drivers by scanning the registry for services that have an "Instances" subkey with "Altitude" values. Filter drivers (e.g., antivirus file system filters) register at specific altitudes.

## MITRE ATT&CK

- T1518.001 - Software Discovery: Security Software Discovery

## Arguments

- `str`: Hostname (empty for localhost, or remote hostname for remote registry).

## Build

```text
cd bofs/sa/enum_filter_driver
cargo make
```

## Example

```text
beacon> enum_filter_driver <packed-arguments>
Total filter drivers found: <value>
<value> <value> <value>
<value> <value> <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
