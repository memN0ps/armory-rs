# setthreadcontext

Injects shellcode into a remote process using thread context hijacking. Suspends a thread, modifies its instruction pointer (RIP) to point at the shellcode, then resumes the thread.

## MITRE ATT&CK

- T1055.003 - Process Injection: Thread Execution Hijacking

## Arguments

- `int`: Target process ID.
- `bin`: Shellcode to inject.

## Build

```text
cd bofs/injection/setthreadcontext
cargo make
```

## Example

```text
beacon> setthreadcontext <packed-arguments>
SUCCESS: Thread <value> hijacked, RIP set to shellcode at <value>
SetThreadContext injection into PID: <value>
No thread found in PID <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
