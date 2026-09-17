# startwebclient

Starts the Windows WebClient service from a standard user context by emitting its documented service-trigger ETW event, then verifies the resulting service state.

## MITRE ATT&CK

- T1569.002 - System Services: Service Execution

## Arguments

No arguments.

## Build

```text
cd bofs/remote/startwebclient
cargo make
```

## Example

```text
beacon> inline-execute /path/to/startwebclient.x64.o
[+] WebClient started and the running state was verified.
[*] WebClient is stopped. Emitting the service trigger.
[+] WebClient is already running.
```
