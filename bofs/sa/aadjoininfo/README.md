# aadjoininfo

Retrieves Azure AD / Entra ID join information for the local device using NetGetAadJoinInformation. Dynamically loads the function from netapi32.dll via LoadLibraryA/GetProcAddress to avoid linker issues with mingw.

## MITRE ATT&CK

- T1087.004 - Account Discovery: Cloud Account

## Arguments

No arguments.

## Build

```text
cd bofs/sa/aadjoininfo
cargo make
```

## Example

```text
beacon> inline-execute /path/to/aadjoininfo.x64.o
No Azure AD join information available.
Azure AD Join Information:
Join Type:        <value>
```
