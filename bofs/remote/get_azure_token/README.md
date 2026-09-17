# get_azure_token

Reads cached Azure/Office OAuth tokens from the Token Broker cache at `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\`. Enumerates and reads token cache files, printing their contents for offline analysis.

## MITRE ATT&CK

- T1528 - Steal Application Access Token

## Arguments

No arguments.

## Build

```text
cd bofs/remote/get_azure_token
cargo make
```

## Example

```text
beacon> inline-execute /path/to/get_azure_token.x64.o
SUCCESS.
get_azure_token: Reading Azure/Office OAuth token cache
Checked <value> cache files, found <value> token artifact(s)
```
