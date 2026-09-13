//! Registry callback inventory and reversible list isolation.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, write_u32, write_u64, zero},
    kernel::KernelContext,
    modules::SystemModules,
    output::Output,
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const MAX_CALLBACKS: usize = 128;
const ENTRY_BYTES: usize = 80;
const JOURNAL_BYTES: usize = 72;
const JOURNAL_MAGIC: u32 = 0x4752_524b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3147_5252_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 57, 68, 52, 50, 46, 116, 109, 112, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAction {
    List,
    Disable,
    Cycle,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistryLayout {
    list_head: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistrySnapshot {
    forward: u64,
    backward: u64,
    count: usize,
    fingerprint: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistryJournal {
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    list_rva: u32,
    count: u32,
    original_forward: u64,
    original_backward: u64,
    fingerprint: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistryError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: RegistryAction, output: &mut Output) {
    let result = match action {
        RegistryAction::List => inventory(adapter, output),
        RegistryAction::Disable | RegistryAction::Cycle => change(adapter, action, output),
        RegistryAction::Restore => restore(adapter, output),
    };

    match result {
        Ok(()) => output.line(match action {
            RegistryAction::List => "[+] Registry callback inventory complete; no changes made",
            RegistryAction::Cycle => {
                "[+] Registry callback cycle complete; the full list was restored"
            }
            RegistryAction::Disable => {
                "[+] Registry callback list isolated; run `registry restore` when finished"
            }
            RegistryAction::Restore => {
                "[+] Registry callback list restored; recovery record removed"
            }
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Registry callback action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn inventory<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), RegistryError> {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    output.line("[*] Enumerating registry callbacks");
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let kernel = session.kernel;
    let (adapter, modules, _, _) = session.parts();
    let layout = resolve_layout(kernel)?;
    let first = capture(adapter, modules, layout, true, output)?;
    let second = capture(adapter, modules, layout, false, output)?;

    if first != second {
        return Err(registry_error("registry-list-stability", 1237));
    }

    session.close().map_err(|error| RegistryError {
        stage: "adapter-close",
        code: error.code(),
        rollback: false,
        recovery_retained: false,
    })?;
    let _ = writeln!(
        output,
        "[*] {} callbacks; exact list fingerprint matched on repeat read",
        first.count
    );

    Ok(())
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    action: RegistryAction,
    output: &mut Output,
) -> Result<(), RegistryError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    output.line(match action {
        RegistryAction::Cycle => "[*] Cycling the complete registry callback list",
        _ => "[*] Isolating the complete registry callback list",
    });
    output.line("[*] Risk R3: this affects every registered registry callback until restoration");
    let mut session = KernelSession::open(adapter, REQUIRED, 16).map_err(session_error)?;
    let kernel = session.kernel;
    let (adapter, modules, _, _) = session.parts();
    let layout = resolve_layout(kernel)?;
    let before = capture(adapter, modules, layout, false, output)?;
    let confirmed = capture(adapter, modules, layout, false, output)?;

    if before != confirmed
        || before.count == 0
        || before.forward == layout.list_head
        || before.backward == layout.list_head
    {
        return Err(registry_error("registry-precheck-stability", 1237));
    }

    let journal = RegistryJournal::new(kernel.profile, before);
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let mut isolated_head = [0_u8; 16];
    write_u64(&mut isolated_head, 0, layout.list_head);
    write_u64(&mut isolated_head, 8, layout.list_head);
    let write_result = adapter.write_kernel(layout.list_head, &isolated_head);
    zero(&mut isolated_head);
    let changed = capture(adapter, modules, layout, false, output);
    let detached = validate_chain(
        adapter,
        modules,
        layout,
        journal.original_forward,
        journal.original_backward,
        false,
        output,
    );
    let changed_valid = write_result.is_ok()
        && changed.as_ref().is_ok_and(|snapshot| {
            snapshot.forward == layout.list_head
                && snapshot.backward == layout.list_head
                && snapshot.count == 0
        })
        && detached
            .as_ref()
            .is_ok_and(|snapshot| exact_saved_chain(*snapshot, journal));

    if !changed_valid {
        let rollback = restore_exact(adapter, modules, layout, journal, output).is_ok();

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        let code = write_result
            .err()
            .map(|error| error.code())
            .or_else(|| changed.err().map(|error| error.code))
            .or_else(|| detached.err().map(|error| error.code))
            .unwrap_or(13);
        zero(&mut record);
        return Err(RegistryError {
            stage: "registry-isolation-readback",
            code,
            rollback,
            recovery_retained: !rollback,
        });
    }

    let _ = writeln!(
        output,
        "[*] List head isolated; {} callbacks remain in the verified detached chain",
        before.count
    );

    if matches!(action, RegistryAction::Cycle) {
        restore_exact(adapter, modules, layout, journal, output)?;
        RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
        output.line("[*] Full list head, chain, count, and fingerprint restored exactly");
    }

    zero(&mut record);
    session.close().map_err(|error| RegistryError {
        stage: "adapter-close",
        code: error.code(),
        rollback: matches!(action, RegistryAction::Cycle),
        recovery_retained: matches!(action, RegistryAction::Disable),
    })?;

    Ok(())
}

fn restore<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), RegistryError> {
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = RegistryJournal::decode(&record)
        .ok_or_else(|| retained_error("registry-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 16).map_err(session_error)?;
    let kernel = session.kernel;

    if !journal.matches_profile(kernel.profile) {
        return Err(retained_error("registry-recovery-profile", 13));
    }

    let (adapter, modules, _, _) = session.parts();
    let layout = resolve_layout(kernel)?;
    let restored = restore_exact(adapter, modules, layout, journal, output)?;
    let confirmed = capture(adapter, modules, layout, false, output)?;

    if restored != confirmed || !exact_saved_chain(restored, journal) {
        return Err(retained_error("registry-restore-stability", 1237));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| RegistryError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;

    Ok(())
}

fn resolve_layout(kernel: KernelContext) -> Result<RegistryLayout, RegistryError> {
    let rva = kernel.profile.value(KernelField::RegistryCallbackListRva);

    if rva == 0
        || (rva as u64)
            .checked_add(16)
            .is_none_or(|end| end > kernel.profile.value(KernelField::ImageSize) as u64)
    {
        return Err(registry_error("registry-profile", 50));
    }

    let list_head = kernel
        .base
        .checked_add(rva as u64)
        .filter(|address| is_kernel_pointer(*address) && address & 15 == 0)
        .ok_or_else(|| registry_error("registry-list-address", 487))?;

    Ok(RegistryLayout { list_head })
}

fn capture<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    layout: RegistryLayout,
    emit: bool,
    output: &mut Output,
) -> Result<RegistrySnapshot, RegistryError> {
    let mut head = [0_u8; 16];
    adapter
        .read_kernel(layout.list_head, &mut head)
        .map_err(|error| adapter_error("registry-list-head-read", error.code()))?;
    let forward = read_u64(&head, 0).unwrap_or(0);
    let backward = read_u64(&head, 8).unwrap_or(0);
    zero(&mut head);

    if !list_pointer(forward, layout.list_head) || !list_pointer(backward, layout.list_head) {
        return Err(registry_error("registry-list-head", 13));
    }

    validate_chain(adapter, modules, layout, forward, backward, emit, output)
}

fn validate_chain<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    layout: RegistryLayout,
    forward: u64,
    backward: u64,
    emit: bool,
    output: &mut Output,
) -> Result<RegistrySnapshot, RegistryError> {
    let mut current = forward;
    let mut previous = layout.list_head;
    let mut count = 0;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;

    while current != layout.list_head && count < MAX_CALLBACKS {
        if !is_kernel_pointer(current) || current & 7 != 0 {
            return Err(registry_error("registry-entry-pointer", 487));
        }

        let mut entry = [0_u8; ENTRY_BYTES];
        adapter
            .read_kernel(current, &mut entry)
            .map_err(|error| adapter_error("registry-entry-read", error.code()))?;
        let next = read_u64(&entry, 0).unwrap_or(0);
        let back = read_u64(&entry, 8).unwrap_or(0);
        let cookie = read_u64(&entry, 0x18).unwrap_or(0);
        let function = read_u64(&entry, 0x28).unwrap_or(0);
        zero(&mut entry);

        if back != previous || !list_pointer(next, layout.list_head) || !is_kernel_pointer(function)
        {
            return Err(registry_error("registry-entry-invariant", 13));
        }

        let owner = modules
            .owner(function)
            .ok_or_else(|| registry_error("registry-callback-attribution", 1168))?;
        let name = owner
            .basename()
            .and_then(|name| core::str::from_utf8(name).ok())
            .unwrap_or("unknown");
        let rva = function
            .checked_sub(owner.base())
            .filter(|rva| *rva <= u32::MAX as u64)
            .ok_or_else(|| registry_error("registry-callback-rva", 13))? as u32;

        if emit {
            let _ = writeln!(output, "[*] Callback {:>2} {}+0x{:08x}", count, name, rva);
        }

        for value in [current, next, back, cookie, function] {
            fingerprint = mix_u64(fingerprint, value);
        }

        previous = current;
        current = next;
        count += 1;
    }

    if current != layout.list_head || previous != backward {
        return Err(registry_error("registry-list-boundary", 13));
    }

    Ok(RegistrySnapshot {
        forward,
        backward,
        count,
        fingerprint,
    })
}

fn restore_exact<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    layout: RegistryLayout,
    journal: RegistryJournal,
    output: &mut Output,
) -> Result<RegistrySnapshot, RegistryError> {
    let current = capture(adapter, modules, layout, false, output)?;

    if exact_saved_chain(current, journal) {
        return Ok(current);
    }

    if current.forward != layout.list_head || current.backward != layout.list_head {
        return Err(retained_error("registry-concurrent-registration", 170));
    }

    let detached = validate_chain(
        adapter,
        modules,
        layout,
        journal.original_forward,
        journal.original_backward,
        false,
        output,
    )?;

    if !exact_saved_chain(detached, journal) {
        return Err(retained_error("registry-detached-chain-changed", 1237));
    }

    let mut original_head = [0_u8; 16];
    write_u64(&mut original_head, 0, journal.original_forward);
    write_u64(&mut original_head, 8, journal.original_backward);
    let write = adapter.write_kernel(layout.list_head, &original_head);
    zero(&mut original_head);
    write.map_err(|error| RegistryError {
        stage: "registry-restore-write",
        code: error.code(),
        rollback: false,
        recovery_retained: true,
    })?;
    let restored = capture(adapter, modules, layout, false, output)?;

    if !exact_saved_chain(restored, journal) {
        return Err(retained_error("registry-restore-readback", 29));
    }

    Ok(restored)
}

impl RegistryJournal {
    fn new(profile: &KernelProfile, snapshot: RegistrySnapshot) -> Self {
        Self {
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            list_rva: profile.value(KernelField::RegistryCallbackListRva),
            count: snapshot.count as u32,
            original_forward: snapshot.forward,
            original_backward: snapshot.backward,
            fingerprint: snapshot.fingerprint,
        }
    }

    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.kernel_timestamp);
        write_u32(&mut output, 16, self.kernel_checksum);
        write_u32(&mut output, 20, self.kernel_image_size);
        write_u32(&mut output, 24, self.list_rva);
        write_u32(&mut output, 28, self.count);
        write_u64(&mut output, 32, self.original_forward);
        write_u64(&mut output, 40, self.original_backward);
        write_u64(&mut output, 48, self.fingerprint);
        write_u64(&mut output, 56, JOURNAL_NONCE);
        let integrity = checksum(&output[..64]);
        write_u64(&mut output, 64, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u64(input, 56)? != JOURNAL_NONCE
            || read_u64(input, 64)? != checksum(&input[..64])
        {
            return None;
        }

        let journal = Self {
            kernel_timestamp: read_u32(input, 12)?,
            kernel_checksum: read_u32(input, 16)?,
            kernel_image_size: read_u32(input, 20)?,
            list_rva: read_u32(input, 24)?,
            count: read_u32(input, 28)?,
            original_forward: read_u64(input, 32)?,
            original_backward: read_u64(input, 40)?,
            fingerprint: read_u64(input, 48)?,
        };

        if journal.count == 0
            || journal.count as usize > MAX_CALLBACKS
            || !is_kernel_pointer(journal.original_forward)
            || !is_kernel_pointer(journal.original_backward)
            || journal.original_forward & 7 != 0
            || journal.original_backward & 7 != 0
        {
            return None;
        }

        Some(journal)
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
            && self.list_rva == profile.value(KernelField::RegistryCallbackListRva)
    }
}

fn exact_saved_chain(snapshot: RegistrySnapshot, journal: RegistryJournal) -> bool {
    snapshot.forward == journal.original_forward
        && snapshot.backward == journal.original_backward
        && snapshot.count == journal.count as usize
        && snapshot.fingerprint == journal.fingerprint
}

fn list_pointer(value: u64, head: u64) -> bool {
    value == head || (is_kernel_pointer(value) && value & 7 == 0)
}

fn mix_u64(mut hash: u64, mut value: u64) -> u64 {
    for _ in 0..8 {
        hash ^= value & 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        value >>= 8;
    }

    hash
}

const fn registry_error(stage: &'static str, code: u32) -> RegistryError {
    RegistryError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> RegistryError {
    RegistryError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn adapter_error(stage: &'static str, code: u32) -> RegistryError {
    registry_error(stage, code)
}

const fn session_error(error: crate::session::SessionError) -> RegistryError {
    RegistryError {
        stage: error.stage,
        code: error.code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn recovery_error(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> RegistryError {
    RegistryError {
        stage: error.stage(),
        code: error.code(),
        rollback,
        recovery_retained,
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trip_is_exact() {
        let journal = RegistryJournal {
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            list_rva: 4,
            count: 5,
            original_forward: 0xffff_8000_0000_1000,
            original_backward: 0xffff_8000_0000_2000,
            fingerprint: 6,
        };

        assert_eq!(RegistryJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = RegistryJournal {
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            list_rva: 4,
            count: 1,
            original_forward: 0xffff_8000_0000_1000,
            original_backward: 0xffff_8000_0000_2000,
            fingerprint: 6,
        }
        .encode();
        record[24] ^= 1;

        assert_eq!(RegistryJournal::decode(&record), None);
    }
}
