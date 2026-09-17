# wmi_query

Executes a bounded WQL query against a local or remote WMI namespace and prints the returned non-system properties.

## MITRE ATT&CK

- T1047 - Windows Management Instrumentation

## Arguments

- `str`: Hostname, or an empty string for localhost.
- `str`: WMI namespace, for example `root\cimv2`.
- `str`: WQL query, for example `SELECT Caption FROM Win32_OperatingSystem`.

## Build

```text
cd bofs/sa/wmi_query
cargo make
```

## Example

```text
beacon> wmi_query <packed-arguments>
<property output limit reached>
WMI query: <value> | <value>
<variant type <value>>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
