# comprobe

Tests whether one exact CLSID can be activated with an optional interface identifier and an explicit activation context. The object is immediately released. COM activation can load a DLL or start a local COM server.

## MITRE ATT&CK

- T1218 - System Binary Proxy Execution

## Arguments

- Three packed strings: CLSID, IID or empty for IUnknown, and inproc, local, or both.

## Build

```text
cd bofs/remote/comprobe
cargo make
```

## Example

```text
beacon> comprobe <packed-arguments>
COM activation probe | CLSID=<value> | IID=<value>
local-server: <value> (0x<value>)
in-process: <value> (0x<value>)
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
