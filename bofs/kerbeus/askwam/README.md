# askwam

Requests an access token silently through Windows Web Account Manager (WAM) in the current user's context. It can enumerate WAM accounts, select an account by canonical ID or exact username, request v1 resource or v2 scope tokens, and add Continuous Access Evaluation claims. It does not read WAM cache files, show an interactive prompt, or start a worker thread. Based on the MIT-licensed askWAM research by Dirk-jan Mollema.

## MITRE ATT&CK

- T1528 - Steal Application Access Token
- T1555 - Credentials from Password Stores

## Arguments

- `str`: Client ID, or an empty string for the Microsoft Teams default.
- `str`: OAuth scope, or an empty string for Microsoft Graph `.default`.
- `str`: OAuth resource, or an empty string to use the scope flow.
- `str`: Authority, or an empty string for `organizations`.
- `str`: Claims JSON, or an empty string.
- `str`: Canonical WAM account ID, or an empty string.
- `str`: Exact username selector, or an empty string.
- `int`: Timeout in seconds from 1 through 300.
- `int`: Hide token output: `0` or `1`.
- `int`: Request CAE claim `cp1`: `0` or `1`.
- `int`: Enumerate WAM accounts instead of requesting a token: `0` or `1`.

## Build

```text
cd bofs/kerbeus/askwam
cargo make
```

## Example

```text
beacon> askwam <packed-arguments>
account enumeration cannot be combined with an account selector
WAM success: requestMode=<value> tokenLength=<value> claimsRequested=<value>
WAM account enumeration status: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
