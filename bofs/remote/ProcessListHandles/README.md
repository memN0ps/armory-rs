# ProcessListHandles

Lists open handles in a target process by calling `NtQuerySystemInformation` with the `SystemHandleInformation` class (16) and filtering results by the specified process ID. For each matching handle, prints the handle value, object type index, and granted access mask.

## MITRE ATT&CK

- T1057 - Process Discovery

## Arguments

- `int`: Target process ID.

## Build

```text
cd bofs/remote/ProcessListHandles
cargo make
```

## Example

```text
beacon> ProcessListHandles <packed-arguments>
Total handles for PID <value>: <value>
Listing handles for PID: <value>
0x<value> <value> 0x<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
