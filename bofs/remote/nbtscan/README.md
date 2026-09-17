# nbtscan

Sends a bounded NBSTAT query to one IPv4 address or a CIDR containing at most 64 addresses. It reports returned NetBIOS names and MAC addresses.

## MITRE ATT&CK

- T1018 - Remote System Discovery
- T1049 - System Network Connections Discovery

## Arguments

- `nbtscan <ipv4-or-cidr> <timeout_ms 50-5000>`

## Build

```text
cd bofs/remote/nbtscan
cargo make
```

## Example

```text
beacon> nbtscan <packed-arguments>
Scan complete | checked=<value> | responses=<value> | parse/send errors=<value>
<value>.<value>.<value>.<value> | mac=<value>:<value>:<value>:<value>:<value>:<value>
NetBIOS name scan | target=<value> | addresses=<value> | timeout=<value>ms
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
