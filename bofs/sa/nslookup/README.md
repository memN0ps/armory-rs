# nslookup

Performs DNS queries for a domain name using DnsQuery_A. Supports specifying a custom DNS server and record type.

## MITRE ATT&CK

- T1018 - Remote System Discovery

## Arguments

- `str`: Domain name to query.
- `short`: DNS record type (1=A, 5=CNAME, 28=AAAA, etc.).
- `str`: DNS server IP (empty for system default).

## Build

```text
cd bofs/sa/nslookup
cargo make
```

## Example

```text
beacon> nslookup <packed-arguments>
DNS query results for '<value>' (type <value>):
<value> (<value>): <data>
<value> (CNAME): <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
