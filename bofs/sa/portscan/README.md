# portscan

Checks a bounded list of TCP ports on one IPv4 address with non-blocking connect and an explicit per-port timeout. It performs no banner grabbing.

## MITRE ATT&CK

- T1046 - Network Service Discovery

## Arguments

- Two packed strings followed by one packed int: IPv4 address, comma-separated ports or top20, and timeout in milliseconds from 1 through 5000.

## Build

```text
cd bofs/sa/portscan
cargo make
```

## Example

```text
beacon> portscan <packed-arguments>
Scan complete | checked=<value> | open=<value> | errors=<value>
Ports must be top20, a comma list, or bounded ranges (maximum 256 ports).
IPv4 address is invalid. Hostname resolution is not performed.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
