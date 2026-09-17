# adv_audit_policies

Queries advanced audit policy settings using AuditQuerySystemPolicy. Enumerates well-known audit subcategories and reports whether success and/or failure auditing is enabled for each.

## MITRE ATT&CK

- T1562.002 - Impair Defenses: Disable Windows Event Logging

## Arguments

No arguments.

## Build

```text
cd bofs/sa/adv_audit_policies
cargo make
```

## Example

```text
beacon> inline-execute /path/to/adv_audit_policies.x64.o
=== Audit Policy Query Complete ===
=== Advanced Audit Policy Settings ===
```
