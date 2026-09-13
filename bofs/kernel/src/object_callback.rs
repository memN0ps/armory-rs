//! Process and thread object callback inventory and reversible control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, write_u32, write_u64, zero},
    kernel::{KERNEL_HEADER_BYTES, KernelContext, parse_image_identity},
    modules::{ModuleEntry, SystemModules},
    output::Output,
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const MAX_CALLBACKS: usize = 128;
const OBJECT_TYPE_BYTES: usize = 216;
const ENTRY_BYTES: usize = 64;
const TARGET_NAME_BYTES: usize = 64;
const JOURNAL_BYTES: usize = 144;
const JOURNAL_MAGIC: u32 = 0x424f_524b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3142_4f52_4e52_4b00;
const PROCESS_OBJECT_KEY: u32 = 0x636f_7250;
const THREAD_OBJECT_KEY: u32 = 0x6572_6854;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Process,
    Thread,
}

impl ObjectKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Thread => "thread",
        }
    }

    const fn id(self) -> u32 {
        match self {
            Self::Process => 1,
            Self::Thread => 2,
        }
    }

    const fn export_field(self) -> KernelField {
        match self {
            Self::Process => KernelField::PsProcessTypeRva,
            Self::Thread => KernelField::PsThreadTypeRva,
        }
    }

    const fn expected_key(self) -> u32 {
        match self {
            Self::Process => PROCESS_OBJECT_KEY,
            Self::Thread => THREAD_OBJECT_KEY,
        }
    }

    const fn recovery_name(self) -> &'static [u16] {
        const PROCESS: &[u16] = &[99, 97, 99, 104, 101, 70, 55, 51, 48, 46, 116, 109, 112, 0];
        const THREAD: &[u16] = &[99, 97, 99, 104, 101, 67, 49, 56, 52, 46, 116, 109, 112, 0];

        match self {
            Self::Process => PROCESS,
            Self::Thread => THREAD,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectAction {
    List,
    Disable(ObjectTarget),
    Cycle(ObjectTarget),
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectTarget {
    name: [u8; TARGET_NAME_BYTES],
    name_length: u8,
    operations: u32,
    pre_rva: u32,
    post_rva: u32,
}

impl ObjectTarget {
    pub fn new(name: &str, operations: u32, pre_rva: u32, post_rva: u32) -> Option<Self> {
        if name.is_empty()
            || name.len() >= TARGET_NAME_BYTES
            || !name.bytes().all(valid_name_byte)
            || operations == 0
            || operations & !3 != 0
            || (pre_rva == 0 && post_rva == 0)
        {
            return None;
        }

        let mut target = Self {
            name: [0; TARGET_NAME_BYTES],
            name_length: name.len() as u8,
            operations,
            pre_rva,
            post_rva,
        };
        target.name[..name.len()].copy_from_slice(name.as_bytes());

        Some(target)
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_length as usize]
    }

    fn display_name(&self) -> &str {
        core::str::from_utf8(self.name()).unwrap_or("unknown")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectLayout {
    object_type: u64,
    list_head: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectEntry {
    address: u64,
    next: u64,
    back: u64,
    operations: u32,
    enabled: u32,
    registration: u64,
    object_type: u64,
    pre_operation: u64,
    post_operation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectSnapshot {
    items: usize,
    routines: usize,
    fingerprint: u64,
    target: Option<ObjectEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectJournal {
    kind: ObjectKind,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    target_timestamp: u32,
    target_checksum: u32,
    target_image_size: u32,
    target: ObjectTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(
    adapter: &mut A,
    kind: ObjectKind,
    action: ObjectAction,
    output: &mut Output,
) {
    let result = match action {
        ObjectAction::List => inventory(adapter, kind, output),
        ObjectAction::Disable(target) | ObjectAction::Cycle(target) => {
            change(adapter, kind, action, target, output)
        }
        ObjectAction::Restore => restore(adapter, kind, output),
    };

    match result {
        Ok(()) => output.line(match action {
            ObjectAction::List => "[+] Object callback inventory complete; no changes made",
            ObjectAction::Cycle(_) => "[+] Object callback cycle complete; original state restored",
            ObjectAction::Disable(_) => {
                "[+] Object callback disabled; run `object <type> restore` when finished"
            }
            ObjectAction::Restore => "[+] Object callback restored; recovery record removed",
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Object callback action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn inventory<A: KernelAdapter>(
    adapter: &mut A,
    kind: ObjectKind,
    output: &mut Output,
) -> Result<(), ObjectError> {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    let _ = writeln!(output, "[*] Enumerating {} object callbacks", kind.name());
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let (adapter, modules, kernel, _) = session.parts();
    let layout = resolve_layout(adapter, kernel, kind)?;
    let first = walk(adapter, modules, layout, None, true, output)?;
    let second = walk(adapter, modules, layout, None, false, output)?;

    if first != second {
        return Err(object_error("object-list-stability", 1237));
    }

    session.close().map_err(|error| ObjectError {
        stage: "adapter-close",
        code: error.code(),
        rollback: false,
        recovery_retained: false,
    })?;
    let _ = writeln!(
        output,
        "[*] {} entries; {} pre/post routines; repeat read matched",
        first.items, first.routines
    );

    Ok(())
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    kind: ObjectKind,
    action: ObjectAction,
    target: ObjectTarget,
    output: &mut Output,
) -> Result<(), ObjectError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    let _ = writeln!(
        output,
        "[*] {} {} object callback from {}",
        match action {
            ObjectAction::Cycle(_) => "Cycling",
            _ => "Disabling",
        },
        kind.name(),
        target.display_name()
    );
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel = session.kernel;
    let (adapter, modules, _, _) = session.parts();
    let layout = resolve_layout(adapter, kernel, kind)?;
    let module = exact_target_module(adapter, modules, target)?;
    let first = walk(adapter, modules, layout, Some(target), false, output)?;
    let second = walk(adapter, modules, layout, Some(target), false, output)?;
    let before = first
        .target
        .ok_or_else(|| object_error("object-target-not-found", 1168))?;

    if first != second || before.enabled != 1 {
        return Err(object_error("object-target-stability", 1237));
    }

    let identity = read_target_identity(adapter, module)?;
    let journal = ObjectJournal::new(kind, kernel.profile, identity, target);
    let mut record = journal.encode();
    RecoveryStore::write_new(kind.recovery_name(), &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let enabled_address = before
        .address
        .checked_add(0x14)
        .ok_or_else(|| object_error("object-enabled-address", 487))?;
    let disabled = 0_u32.to_le_bytes();
    let write_result = adapter.write_kernel(enabled_address, &disabled);
    let changed = walk(adapter, modules, layout, Some(target), false, output);
    let changed_valid = write_result.is_ok()
        && changed.as_ref().is_ok_and(|snapshot| {
            snapshot
                .target
                .is_some_and(|entry| same_entry(&before, &entry) && entry.enabled == 0)
        });

    if !changed_valid {
        let rollback = restore_entry(adapter, modules, layout, target, &before, output);

        if rollback {
            let _ = RecoveryStore::delete(kind.recovery_name());
        }

        let code = write_result
            .err()
            .map(|error| error.code())
            .or_else(|| changed.err().map(|error| error.code))
            .unwrap_or(13);
        zero(&mut record);
        return Err(ObjectError {
            stage: "object-disable-readback",
            code,
            rollback,
            recovery_retained: !rollback,
        });
    }

    output.line("[*] Enabled field changed from 1 to 0; list links were not modified");

    if matches!(action, ObjectAction::Cycle(_)) {
        if !restore_entry(adapter, modules, layout, target, &before, output) {
            zero(&mut record);
            return Err(ObjectError {
                stage: "object-cycle-restore",
                code: 13,
                rollback: false,
                recovery_retained: true,
            });
        }

        RecoveryStore::delete(kind.recovery_name())
            .map_err(|error| recovery_error(error, true, true))?;
        output.line("[*] Enabled field restored to 1; exact entry readback matched");
    }

    zero(&mut record);
    session.close().map_err(|error| ObjectError {
        stage: "adapter-close",
        code: error.code(),
        rollback: matches!(action, ObjectAction::Cycle(_)),
        recovery_retained: matches!(action, ObjectAction::Disable(_)),
    })?;

    Ok(())
}

fn restore<A: KernelAdapter>(
    adapter: &mut A,
    kind: ObjectKind,
    output: &mut Output,
) -> Result<(), ObjectError> {
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(kind.recovery_name(), &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = ObjectJournal::decode(&record)
        .filter(|journal| journal.kind == kind)
        .ok_or_else(|| object_error_retained("object-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel = session.kernel;

    if !journal.matches_profile(kernel.profile) {
        return Err(object_error_retained("object-recovery-profile", 13));
    }

    let (adapter, modules, _, _) = session.parts();
    let layout = resolve_layout(adapter, kernel, kind)?;
    let module = exact_target_module(adapter, modules, journal.target)?;
    let identity = read_target_identity(adapter, module)?;

    if identity != journal.target_identity() {
        return Err(object_error_retained("object-recovery-target", 13));
    }

    let current = walk(
        adapter,
        modules,
        layout,
        Some(journal.target),
        false,
        output,
    )?
    .target
    .ok_or_else(|| object_error_retained("object-recovery-target-missing", 1168))?;

    if current.enabled == 0 {
        if !restore_entry(adapter, modules, layout, journal.target, &current, output) {
            return Err(object_error_retained("object-restore-readback", 13));
        }
    } else if current.enabled != 1 {
        return Err(object_error_retained("object-restore-state", 13));
    }

    RecoveryStore::delete(kind.recovery_name())
        .map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| ObjectError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Object callback is enabled and the exact recovery record was removed");

    Ok(())
}

fn resolve_layout<A: KernelAdapter>(
    adapter: &mut A,
    kernel: KernelContext,
    kind: ObjectKind,
) -> Result<ObjectLayout, ObjectError> {
    let profile = kernel.profile;
    let object_size = profile.value(KernelField::ObjectTypeSize) as usize;
    let key_offset = profile.value(KernelField::ObjectTypeKey) as usize;
    let list_offset = profile.value(KernelField::ObjectTypeCallbackList) as usize;

    if object_size == 0
        || object_size > OBJECT_TYPE_BYTES
        || key_offset
            .checked_add(4)
            .is_none_or(|end| end > object_size)
        || list_offset
            .checked_add(16)
            .is_none_or(|end| end > object_size)
    {
        return Err(object_error("object-profile-layout", 13));
    }

    let export_address = kernel
        .base
        .checked_add(profile.value(kind.export_field()) as u64)
        .ok_or_else(|| object_error("object-type-export", 487))?;
    let mut pointer = [0_u8; 8];
    adapter
        .read_kernel(export_address, &mut pointer)
        .map_err(|error| ObjectError {
            stage: "object-type-pointer-read",
            code: error.code(),
            rollback: false,
            recovery_retained: false,
        })?;
    let object_type = read_u64(&pointer, 0).unwrap_or(0);
    zero(&mut pointer);

    if !is_kernel_pointer(object_type) || object_type & 7 != 0 {
        return Err(object_error("object-type-pointer", 487));
    }

    let mut bytes = [0_u8; OBJECT_TYPE_BYTES];
    adapter
        .read_kernel(object_type, &mut bytes[..object_size])
        .map_err(|error| ObjectError {
            stage: "object-type-read",
            code: error.code(),
            rollback: false,
            recovery_retained: false,
        })?;
    let key = read_u32(&bytes, key_offset).unwrap_or(0);
    zero(&mut bytes);

    if key != kind.expected_key() {
        return Err(object_error("object-type-key", 1306));
    }

    let list_head = object_type
        .checked_add(list_offset as u64)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or_else(|| object_error("object-list-address", 487))?;

    Ok(ObjectLayout {
        object_type,
        list_head,
    })
}

fn walk<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    layout: ObjectLayout,
    target: Option<ObjectTarget>,
    emit: bool,
    output: &mut Output,
) -> Result<ObjectSnapshot, ObjectError> {
    let mut head = [0_u8; 16];
    adapter
        .read_kernel(layout.list_head, &mut head)
        .map_err(|error| adapter_error("object-list-head-read", error.code()))?;
    let forward = read_u64(&head, 0).unwrap_or(0);
    let backward = read_u64(&head, 8).unwrap_or(0);
    zero(&mut head);

    if !list_pointer(forward, layout.list_head) || !list_pointer(backward, layout.list_head) {
        return Err(object_error("object-list-head", 13));
    }

    let mut current = forward;
    let mut previous = layout.list_head;
    let mut items = 0;
    let mut routines = 0;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;
    let mut matched = None;

    while current != layout.list_head && items < MAX_CALLBACKS {
        if !is_kernel_pointer(current) || current & 7 != 0 {
            return Err(object_error("object-entry-pointer", 487));
        }

        let entry = read_entry(adapter, current)?;

        if entry.back != previous
            || !list_pointer(entry.next, layout.list_head)
            || entry.object_type != layout.object_type
            || entry.operations == 0
            || entry.operations & !3 != 0
            || entry.enabled > 1
            || (entry.pre_operation == 0 && entry.post_operation == 0)
            || !is_kernel_pointer(entry.registration)
        {
            return Err(object_error("object-entry-invariant", 13));
        }

        if entry.pre_operation != 0 {
            emit_routine(
                modules,
                "pre",
                items,
                entry,
                entry.pre_operation,
                emit,
                output,
            )?;
            routines += 1;
        }

        if entry.post_operation != 0 {
            emit_routine(
                modules,
                "post",
                items,
                entry,
                entry.post_operation,
                emit,
                output,
            )?;
            routines += 1;
        }

        if let Some(spec) = target
            && target_matches(modules, spec, entry)?
        {
            if matched.is_some() {
                return Err(object_error("object-target-not-unique", 13));
            }

            matched = Some(entry);
        }

        for value in [
            entry.address,
            entry.next,
            entry.back,
            entry.registration,
            entry.object_type,
            entry.pre_operation,
            entry.post_operation,
            entry.operations as u64,
            entry.enabled as u64,
        ] {
            fingerprint = mix_u64(fingerprint, value);
        }

        previous = current;
        current = entry.next;
        items += 1;
    }

    if current != layout.list_head || previous != backward {
        return Err(object_error("object-list-boundary", 13));
    }

    Ok(ObjectSnapshot {
        items,
        routines,
        fingerprint,
        target: matched,
    })
}

fn read_entry<A: KernelAdapter>(adapter: &mut A, address: u64) -> Result<ObjectEntry, ObjectError> {
    let mut bytes = [0_u8; ENTRY_BYTES];
    adapter
        .read_kernel(address, &mut bytes)
        .map_err(|error| adapter_error("object-entry-read", error.code()))?;
    let entry = ObjectEntry {
        address,
        next: read_u64(&bytes, 0).unwrap_or(0),
        back: read_u64(&bytes, 8).unwrap_or(0),
        operations: read_u32(&bytes, 0x10).unwrap_or(0),
        enabled: read_u32(&bytes, 0x14).unwrap_or(u32::MAX),
        registration: read_u64(&bytes, 0x18).unwrap_or(0),
        object_type: read_u64(&bytes, 0x20).unwrap_or(0),
        pre_operation: read_u64(&bytes, 0x28).unwrap_or(0),
        post_operation: read_u64(&bytes, 0x30).unwrap_or(0),
    };
    zero(&mut bytes);

    Ok(entry)
}

fn emit_routine(
    modules: &SystemModules,
    phase: &str,
    index: usize,
    entry: ObjectEntry,
    function: u64,
    emit: bool,
    output: &mut Output,
) -> Result<(), ObjectError> {
    let owner = modules
        .owner(function)
        .ok_or_else(|| object_error("object-callback-attribution", 1168))?;
    let name = owner
        .basename()
        .and_then(|name| core::str::from_utf8(name).ok())
        .unwrap_or("unknown");
    let rva = function
        .checked_sub(owner.base())
        .filter(|rva| *rva <= u32::MAX as u64)
        .ok_or_else(|| object_error("object-callback-rva", 13))? as u32;

    if emit {
        let _ = writeln!(
            output,
            "[*] {:<4} callback {:>2} {:<4} ops=0x{:02x} enabled={} {}+0x{:08x}",
            if entry.object_type == 0 { "?" } else { "obj" },
            index,
            phase,
            entry.operations,
            entry.enabled,
            name,
            rva
        );
    }

    Ok(())
}

fn target_matches(
    modules: &SystemModules,
    target: ObjectTarget,
    entry: ObjectEntry,
) -> Result<bool, ObjectError> {
    if entry.operations != target.operations {
        return Ok(false);
    }

    let module = modules
        .find(target.name())
        .ok_or_else(|| object_error("object-target-module", 1168))?;
    let expected_pre = if target.pre_rva == 0 {
        0
    } else {
        module
            .base()
            .checked_add(target.pre_rva as u64)
            .ok_or_else(|| object_error("object-target-pre-rva", 487))?
    };
    let expected_post = if target.post_rva == 0 {
        0
    } else {
        module
            .base()
            .checked_add(target.post_rva as u64)
            .ok_or_else(|| object_error("object-target-post-rva", 487))?
    };

    Ok(entry.pre_operation == expected_pre && entry.post_operation == expected_post)
}

fn exact_target_module<'a, A: KernelAdapter>(
    adapter: &mut A,
    modules: &'a SystemModules,
    target: ObjectTarget,
) -> Result<&'a ModuleEntry, ObjectError> {
    let module = modules
        .find(target.name())
        .ok_or_else(|| object_error("object-target-module", 1168))?;
    let end = target.pre_rva.max(target.post_rva) as u64;

    if end >= module.image_size() as u64 {
        return Err(object_error("object-target-rva-bounds", 13));
    }

    let _ = read_target_identity(adapter, module)?;

    Ok(module)
}

fn read_target_identity<A: KernelAdapter>(
    adapter: &mut A,
    module: &ModuleEntry,
) -> Result<(u32, u32, u32), ObjectError> {
    let mut headers = [0_u8; KERNEL_HEADER_BYTES];
    adapter
        .read_kernel(module.base(), &mut headers)
        .map_err(|error| adapter_error("object-target-pe-read", error.code()))?;
    let identity =
        parse_image_identity(&headers).ok_or_else(|| object_error("object-target-pe", 13))?;
    zero(&mut headers);

    if identity.image_size != module.image_size() {
        return Err(object_error("object-target-image-size", 13));
    }

    Ok((identity.timestamp, identity.checksum, identity.image_size))
}

fn restore_entry<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
    layout: ObjectLayout,
    target: ObjectTarget,
    before: &ObjectEntry,
    output: &mut Output,
) -> bool {
    let Some(address) = before.address.checked_add(0x14) else {
        return false;
    };

    for _ in 0..3 {
        if adapter.write_kernel(address, &1_u32.to_le_bytes()).is_ok()
            && walk(adapter, modules, layout, Some(target), false, output)
                .ok()
                .and_then(|snapshot| snapshot.target)
                .is_some_and(|entry| same_entry(before, &entry) && entry.enabled == 1)
        {
            return true;
        }
    }

    false
}

fn same_entry(left: &ObjectEntry, right: &ObjectEntry) -> bool {
    left.address == right.address
        && left.next == right.next
        && left.back == right.back
        && left.operations == right.operations
        && left.registration == right.registration
        && left.object_type == right.object_type
        && left.pre_operation == right.pre_operation
        && left.post_operation == right.post_operation
}

impl ObjectJournal {
    fn new(
        kind: ObjectKind,
        profile: &KernelProfile,
        identity: (u32, u32, u32),
        target: ObjectTarget,
    ) -> Self {
        Self {
            kind,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            target_timestamp: identity.0,
            target_checksum: identity.1,
            target_image_size: identity.2,
            target,
        }
    }

    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.kind.id());
        write_u32(&mut output, 16, self.kernel_timestamp);
        write_u32(&mut output, 20, self.kernel_checksum);
        write_u32(&mut output, 24, self.kernel_image_size);
        write_u32(&mut output, 28, self.target_timestamp);
        write_u32(&mut output, 32, self.target_checksum);
        write_u32(&mut output, 36, self.target_image_size);
        write_u32(&mut output, 40, self.target.operations);
        write_u32(&mut output, 44, self.target.pre_rva);
        write_u32(&mut output, 48, self.target.post_rva);
        write_u32(&mut output, 52, 1);
        write_u32(&mut output, 56, 0);
        output[60..124].copy_from_slice(&self.target.name);
        output[124] = self.target.name_length;
        write_u64(&mut output, 128, JOURNAL_NONCE ^ self.kind.id() as u64);
        let integrity = checksum(&output[..136]);
        write_u64(&mut output, 136, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        let kind = match read_u32(input, 12)? {
            1 => ObjectKind::Process,
            2 => ObjectKind::Thread,
            _ => return None,
        };

        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u32(input, 52)? != 1
            || read_u32(input, 56)? != 0
            || read_u64(input, 128)? != JOURNAL_NONCE ^ kind.id() as u64
            || read_u64(input, 136)? != checksum(&input[..136])
        {
            return None;
        }

        let name_length = *input.get(124)? as usize;

        if name_length == 0 || name_length >= TARGET_NAME_BYTES {
            return None;
        }

        let mut name = [0_u8; TARGET_NAME_BYTES];
        name.copy_from_slice(input.get(60..124)?);
        let target = ObjectTarget::new(
            core::str::from_utf8(name.get(..name_length)?).ok()?,
            read_u32(input, 40)?,
            read_u32(input, 44)?,
            read_u32(input, 48)?,
        )?;

        Some(Self {
            kind,
            kernel_timestamp: read_u32(input, 16)?,
            kernel_checksum: read_u32(input, 20)?,
            kernel_image_size: read_u32(input, 24)?,
            target_timestamp: read_u32(input, 28)?,
            target_checksum: read_u32(input, 32)?,
            target_image_size: read_u32(input, 36)?,
            target,
        })
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
    }

    const fn target_identity(self) -> (u32, u32, u32) {
        (
            self.target_timestamp,
            self.target_checksum,
            self.target_image_size,
        )
    }
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

const fn valid_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

const fn object_error(stage: &'static str, code: u32) -> ObjectError {
    ObjectError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn object_error_retained(stage: &'static str, code: u32) -> ObjectError {
    ObjectError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn adapter_error(stage: &'static str, code: u32) -> ObjectError {
    object_error(stage, code)
}

const fn session_error(error: crate::session::SessionError) -> ObjectError {
    ObjectError {
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
) -> ObjectError {
    ObjectError {
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
    use crate::profiles::KERNEL_PROFILES;

    #[test]
    fn target_rejects_unsafe_or_empty_routines() {
        assert!(ObjectTarget::new("sensor.sys", 3, 0x1000, 0x2000).is_some());
        assert!(ObjectTarget::new("..\\sensor.sys", 3, 0x1000, 0x2000).is_none());
        assert!(ObjectTarget::new("sensor.sys", 0, 0x1000, 0x2000).is_none());
        assert!(ObjectTarget::new("sensor.sys", 4, 0x1000, 0x2000).is_none());
        assert!(ObjectTarget::new("sensor.sys", 1, 0, 0).is_none());
    }

    #[test]
    fn journal_round_trip_is_exact() {
        let profile = &KERNEL_PROFILES[0];
        let journal = ObjectJournal::new(
            ObjectKind::Process,
            profile,
            (1, 2, 0x3000),
            ObjectTarget::new("sensor.sys", 3, 0x1000, 0x2000).unwrap(),
        );

        assert_eq!(ObjectJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = ObjectJournal {
            kind: ObjectKind::Thread,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            target_timestamp: 4,
            target_checksum: 5,
            target_image_size: 6,
            target: ObjectTarget::new("sensor.sys", 1, 0x1000, 0).unwrap(),
        }
        .encode();
        record[44] ^= 1;

        assert_eq!(ObjectJournal::decode(&record), None);
    }
}
