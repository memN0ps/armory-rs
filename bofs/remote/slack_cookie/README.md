# slack_cookie

Scans a Slack process's memory for authentication cookies by searching for the "xoxd-" cookie token pattern. Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory.

## MITRE ATT&CK

- T1539 - Steal Web Session Cookie

## Arguments

- `int`: Target Slack process ID.

## Build

```text
cd bofs/remote/slack_cookie
cargo make
```

## Example

```text
beacon> slack_cookie <packed-arguments>
SUCCESS.
slack_cookie: Scanning process <value> for Slack auth cookies (xoxd- prefix)
Scanned <value> regions, found <value> Slack cookie(s)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
