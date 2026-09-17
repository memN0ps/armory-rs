# aisurface

Reports the presence of common local AI applications, coding-agent profiles, editor storage, and MCP configuration files. It does not read configuration contents, tokens, session data, or prompts.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/aisurface
cargo make
```

## Example

```text
beacon> inline-execute /path/to/aisurface.x64.o
Presence only; configuration and session contents are not read.
Artifacts found: <value> | MCP configs: <value> | project directories examined: <value>
Project MCP config | <value>
```
