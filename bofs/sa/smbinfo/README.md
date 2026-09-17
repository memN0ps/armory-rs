# smbinfo

Queries a named Windows host through NetWkstaGetInfo and reports its workstation version, platform, computer name, workgroup, and LAN root.

## MITRE ATT&CK

- T1018 - Remote System Discovery

## Arguments

- `str`: Remote hostname or UNC server name.

## Build

```text
cd bofs/sa/smbinfo
cargo make
```

## Example

```text
beacon> smbinfo <packed-arguments>
Remote workstation information: <value>
Workgroup/domain: <value>
Platform ID: <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
