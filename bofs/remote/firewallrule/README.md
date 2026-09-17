# firewallrule

Queries, adds, or removes one exact named Windows Firewall rule through INetFwPolicy2. Add refuses a name collision. Remove is the explicit rollback action and should be used only with the exact unique name returned by add.

## MITRE ATT&CK

- T1562.004 - Impair Defenses: Disable or Modify System Firewall

## Arguments

- Seven packed strings: action, name, direction, decision, protocol, local ports, and application. For query/remove, pass empty strings after name.

## Build

```text
cd bofs/remote/firewallrule
cargo make
```

## Example

```text
beacon> firewallrule <packed-arguments>
Firewall rule removed: <value>
Rule exists | direction=<value> | action=<value> | protocol=<value> | enabled=<value> | ports=<value> | application=<value>
Firewall rule added: <value>. Run remove with the same exact name to roll it back.
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
