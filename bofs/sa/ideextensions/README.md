# ideextensions

Enumerates bounded per-user extension directories for common Visual Studio Code-compatible editors and remote editor profiles. It reports directory identities and whether a package manifest exists without reading its content.

## MITRE ATT&CK

- T1083 - File and Directory Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/ideextensions
cargo make
```

## Example

```text
beacon> inline-execute /path/to/ideextensions.x64.o
Roots found: <value> | extension manifests: <value><value>
IDE extension discovery
<value> | manifest=yes
```
