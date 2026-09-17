# suspendresume

Suspends or resumes a target process by PID using the undocumented `NtSuspendProcess` / `NtResumeProcess` NT APIs. Attempts to enable `SeDebugPrivilege` first so that elevated processes can be targeted.

## MITRE ATT&CK

- T1106 - Native API

## Arguments

- `option` (short) - 0 = resume, 1 = suspend.
- `pid` (int) - Process ID of the target process.

## Build

```text
cd bofs/remote/suspendresume
cargo make
```

## Example

```text
beacon> suspendresume <packed-arguments>
Successfully <value> process <value>.
SeDebugPrivilege not available (non-fatal).
Attempting to <value> process <value> ...
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
