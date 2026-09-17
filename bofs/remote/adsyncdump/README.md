# adsyncdump

Recovers the on-premises Active Directory connector credential from a local Microsoft Entra Connect server. It queries the local ADSync database, reads and DPAPI-decrypts the matching keyset while impersonating `miiserver.exe`, decrypts the connector configuration, and prints the connector username and password. Run from a SYSTEM context on the Entra Connect server. Based on the MIT-licensed ADSyncDump-BOF by Luke Paris (Paradoxis), which in turn references Dirk-jan Mollema's AD Connect research.

## MITRE ATT&CK

- T1003 - OS Credential Dumping
- T1555 - Credentials from Password Stores
- T1134.001 - Access Token Manipulation: Token Impersonation/Theft

## Arguments

No arguments.

## Build

```text
cd bofs/remote/adsyncdump
cargo make
```

## Example

```text
beacon> inline-execute /path/to/adsyncdump.x64.o
ADSync metadata: instance=<value> entropy=<value> keyset=0x<value>
No supported SQL Server ODBC driver was found: <value>
The ADSync connector username was not found
```
