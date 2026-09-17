# slackKey

Reads Slack API tokens from local storage files under `%APPDATA%\Slack\storage\`. Searches file contents for token patterns such as "xoxs-", "xoxp-", and "xoxb-".

## MITRE ATT&CK

- T1528 - Steal Application Access Token

## Arguments

No arguments.

## Build

```text
cd bofs/remote/slackKey
cargo make
```

## Example

```text
beacon> inline-execute /path/to/slackKey.x64.o
SUCCESS.
Slack storage directory not found - Slack may not be installed.
slackKey: Searching for Slack API tokens in local storage
```
