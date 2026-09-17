# ntqueueapcthread

Injects shellcode into a remote process using APC queue injection. Allocates memory in the target, writes shellcode, then queues an APC to an alertable thread to trigger execution.

## MITRE ATT&CK

- T1055.004 - Process Injection: Asynchronous Procedure Call

## Arguments

- `int`: Target process ID.
- `bin`: Shellcode to inject.

## Build

```text
cd bofs/injection/ntqueueapcthread
cargo make
```

## Example

```text
beacon> ntqueueapcthread <packed-arguments>
SUCCESS: APC queued to thread <value> in PID <value>
NtQueueApcThread injection into PID: <value>
No thread found in PID <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
