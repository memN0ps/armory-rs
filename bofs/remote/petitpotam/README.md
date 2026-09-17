# petitpotam

Calls the encrypted-file-system RPC interface over the remote `lsarpc` named pipe and supplies a bounded UNC path. `EfsRpcOpenFileRaw` is attempted first and `EfsRpcQueryRecoveryAgents` is used as the protocol-correct fallback. Both calls use Microsoft NDR client contracts. Returned RPC allocations and context handles are released before the BOF exits.

## MITRE ATT&CK

- T1187 - Forced Authentication

## Arguments

- `str`: Target server hostname or address.
- `str`: Listener hostname or address for the UNC path.

## Build

```text
cd bofs/remote/petitpotam
cargo make
```

## Example

```text
beacon> petitpotam <packed-arguments>
EFSRPC completed against <value> without a coercion-indicating status (OpenFileRaw <value>, QueryRecoveryAgents <value>). Confirm listener telemetry before claiming forced authentication.
EfsRpcQueryRecoveryAgents reached <value> and attempted the remote UNC path (OpenFileRaw status <value>, fallback status <value>).
EfsRpcOpenFileRaw reached <value> and attempted the remote UNC path (status <value>).
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
