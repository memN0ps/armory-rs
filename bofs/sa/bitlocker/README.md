# bitlocker

Reads the local BitLocker volume snapshot exposed by the Microsoft Volume Encryption WMI provider. It does not change encryption or key protectors.

## MITRE ATT&CK

- T1082 - System Information Discovery

## Arguments

No arguments.

## Build

```text
cd bofs/sa/bitlocker
cargo make
```

## Example

```text
beacon> inline-execute /path/to/bitlocker.x64.o
BitLocker volume status
No encryptable volumes were returned.
device:      <value>
```
