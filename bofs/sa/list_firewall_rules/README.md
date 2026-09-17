# list_firewall_rules

Enumerates Windows Firewall rules by reading directly from the registry at `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`. Each value contains a pipe-delimited firewall rule string. Parses and displays Action, Direction, Protocol, Local Port, Remote Port, Application, and Name.

## MITRE ATT&CK

- T1518 - Software Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/list_firewall_rules
cargo make
```

## Example

```text
beacon> inline-execute /path/to/list_firewall_rules.x64.o
<value> Action=<value> Dir=<value> Proto=<value> LPort=<value> RPort=<value> App=<value>
Windows Firewall Rules (from registry):
Total firewall rules: <value>
```
