# ProcessDestroy

Closes a specific handle in a remote process by using `DuplicateHandle` with `DUPLICATE_CLOSE_SOURCE`. This forces the target process to release the specified handle, which can disrupt the process or its dependent resources.

## MITRE ATT&CK

- T1489 - Service Stop

## Arguments

- `int`: Target process ID.
- `int`: Handle value to close in the target process. This BOF is **DESTRUCTIVE**. Closing handles in a remote process can cause

## Build

```text
cd bofs/remote/ProcessDestroy
cargo make
```

## Example

```text
beacon> ProcessDestroy <packed-arguments>
Successfully closed handle 0x<value> in PID <value>.
Handle value:  0x<value>
Target PID:    <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
