//! ETW Threat Intelligence provider state inspection and reversible control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, write_u32, write_u64, zero},
    output::Output,
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const REGISTRATION_BYTES: usize = 0x70;
const GUID_BYTES: usize = 0x1a8;
const JOURNAL_BYTES: usize = 56;
const JOURNAL_MAGIC: u32 = 0x4954_524b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3149_5452_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 52, 70, 56, 49, 46, 116, 109, 112, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtwTiAction {
    State,
    Disable,
    Cycle,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EtwTiState {
    registration: u64,
    guid_entry: u64,
    enable_mask: u8,
    group_enable_mask: u8,
    host_enable_mask: u8,
    host_group_enable_mask: u8,
    enabled: u32,
    level: u8,
    property: u32,
    match_any: u64,
    match_all: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EtwTiJournal {
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    original_enabled: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EtwTiError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: EtwTiAction, output: &mut Output) {
    let result = match action {
        EtwTiAction::State => inspect(adapter, output),
        EtwTiAction::Disable | EtwTiAction::Cycle => change(adapter, action, output),
        EtwTiAction::Restore => restore(adapter, output),
    };

    match result {
        Ok(()) => output.line(match action {
            EtwTiAction::State => "[+] ETW Threat Intelligence state inspected; no changes made",
            EtwTiAction::Cycle => {
                "[+] ETW Threat Intelligence cycle complete; original state restored"
            }
            EtwTiAction::Disable => {
                "[+] ETW Threat Intelligence disabled; run `etw-ti restore` when finished"
            }
            EtwTiAction::Restore => "[+] ETW Threat Intelligence restored; recovery record removed",
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] ETW Threat Intelligence action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn inspect<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), EtwTiError> {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    output.line("[*] Inspecting ETW Threat Intelligence provider state");
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let kernel = session.kernel;
    let handle = resolve_handle(kernel)?;
    let before = read_state(session.adapter(), kernel.profile, handle)?;
    let after = read_state(session.adapter(), kernel.profile, handle)?;

    if before != after {
        return Err(etw_error("etw-ti-stability", 1237));
    }

    print_state(output, before);
    session.close().map_err(|error| EtwTiError {
        stage: "adapter-close",
        code: error.code(),
        rollback: false,
        recovery_retained: false,
    })?;

    Ok(())
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    action: EtwTiAction,
    output: &mut Output,
) -> Result<(), EtwTiError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    output.line(match action {
        EtwTiAction::Cycle => "[*] Cycling ETW Threat Intelligence provider state",
        _ => "[*] Disabling ETW Threat Intelligence provider state",
    });
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel = session.kernel;
    let handle = resolve_handle(kernel)?;
    let before = read_state(session.adapter(), kernel.profile, handle)?;
    let confirmed = read_state(session.adapter(), kernel.profile, handle)?;

    if before != confirmed || before.enabled != 1 {
        return Err(etw_error("etw-ti-original-state", 13));
    }

    print_state(output, before);
    let journal = EtwTiJournal::new(kernel.profile, before.enabled);
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let address = enabled_address(kernel.profile, before)?;
    let write_result = session
        .adapter()
        .write_kernel(address, &0_u32.to_le_bytes());
    let changed = read_state(session.adapter(), kernel.profile, handle);
    let changed_valid = write_result.is_ok()
        && changed
            .as_ref()
            .is_ok_and(|state| same_provider(before, *state) && state.enabled == 0);

    if !changed_valid {
        let rollback = restore_word(
            session.adapter(),
            kernel.profile,
            handle,
            before,
            before.enabled,
        );

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        let code = write_result
            .err()
            .map(|error| error.code())
            .or_else(|| changed.err().map(|error| error.code))
            .unwrap_or(13);
        zero(&mut record);
        return Err(EtwTiError {
            stage: "etw-ti-disable-readback",
            code,
            rollback,
            recovery_retained: !rollback,
        });
    }

    output.line("[*] Provider Enabled field changed from 1 to 0; readback exact");

    if matches!(action, EtwTiAction::Cycle) {
        if !restore_word(
            session.adapter(),
            kernel.profile,
            handle,
            before,
            before.enabled,
        ) {
            zero(&mut record);
            return Err(EtwTiError {
                stage: "etw-ti-cycle-restore",
                code: 13,
                rollback: false,
                recovery_retained: true,
            });
        }

        RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
        output.line("[*] Provider Enabled field restored to 1; full state matched");
    }

    zero(&mut record);
    session.close().map_err(|error| EtwTiError {
        stage: "adapter-close",
        code: error.code(),
        rollback: matches!(action, EtwTiAction::Cycle),
        recovery_retained: matches!(action, EtwTiAction::Disable),
    })?;

    Ok(())
}

fn restore<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), EtwTiError> {
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = EtwTiJournal::decode(&record)
        .ok_or_else(|| retained_error("etw-ti-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel = session.kernel;

    if !journal.matches_profile(kernel.profile) {
        return Err(retained_error("etw-ti-recovery-profile", 13));
    }

    let handle = resolve_handle(kernel)?;
    let current = read_state(session.adapter(), kernel.profile, handle)?;

    if current.enabled == 0 {
        if !restore_word(
            session.adapter(),
            kernel.profile,
            handle,
            current,
            journal.original_enabled,
        ) {
            return Err(retained_error("etw-ti-restore-readback", 13));
        }
    } else if current.enabled != journal.original_enabled {
        return Err(retained_error("etw-ti-restore-state", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| EtwTiError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Provider Enabled field is 1 and the exact recovery record was removed");

    Ok(())
}

fn resolve_handle(kernel: crate::kernel::KernelContext) -> Result<u64, EtwTiError> {
    let rva = kernel.profile.value(KernelField::EtwTiHandleRva);

    if rva == 0
        || (rva as u64)
            .checked_add(8)
            .is_none_or(|end| end > kernel.profile.value(KernelField::ImageSize) as u64)
    {
        return Err(etw_error("etw-ti-profile", 50));
    }

    kernel
        .base
        .checked_add(rva as u64)
        .filter(|address| is_kernel_pointer(*address) && address & 7 == 0)
        .ok_or_else(|| etw_error("etw-ti-handle-address", 487))
}

fn read_state<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    handle: u64,
) -> Result<EtwTiState, EtwTiError> {
    let registration_size = profile.value(KernelField::EtwRegEntrySize) as usize;
    let guid_size = profile.value(KernelField::EtwGuidEntrySize) as usize;
    let reg_guid = profile.value(KernelField::EtwRegGuidEntry) as usize;
    let reg_mask = profile.value(KernelField::EtwRegEnableMask) as usize;
    let provider = profile.value(KernelField::EtwGuidProviderEnableInfo) as usize;
    let enabled = profile.value(KernelField::TraceEnableIsEnabled) as usize;
    let level = profile.value(KernelField::TraceEnableLevel) as usize;
    let property = profile.value(KernelField::TraceEnableProperty) as usize;
    let match_any = profile.value(KernelField::TraceEnableMatchAny) as usize;
    let match_all = profile.value(KernelField::TraceEnableMatchAll) as usize;

    if registration_size == 0
        || registration_size > REGISTRATION_BYTES
        || guid_size == 0
        || guid_size > GUID_BYTES
        || reg_guid
            .checked_add(8)
            .is_none_or(|end| end > registration_size)
        || reg_mask
            .checked_add(4)
            .is_none_or(|end| end > registration_size)
        || provider
            .checked_add(match_all)
            .and_then(|offset| offset.checked_add(8))
            .is_none_or(|end| end > guid_size)
        || provider
            .checked_add(match_any)
            .and_then(|offset| offset.checked_add(8))
            .is_none_or(|end| end > guid_size)
        || provider
            .checked_add(property)
            .and_then(|offset| offset.checked_add(4))
            .is_none_or(|end| end > guid_size)
        || provider
            .checked_add(enabled)
            .and_then(|offset| offset.checked_add(4))
            .is_none_or(|end| end > guid_size)
        || provider
            .checked_add(level)
            .is_none_or(|offset| offset >= guid_size)
    {
        return Err(etw_error("etw-ti-profile-layout", 13));
    }

    let mut pointer = [0_u8; 8];
    adapter
        .read_kernel(handle, &mut pointer)
        .map_err(|error| adapter_error("etw-ti-registration-handle", error.code()))?;
    let registration = read_u64(&pointer, 0).unwrap_or(0);
    zero(&mut pointer);

    if !is_kernel_pointer(registration) || registration & 7 != 0 {
        return Err(etw_error("etw-ti-registration-pointer", 487));
    }

    let mut registration_bytes = [0_u8; REGISTRATION_BYTES];
    adapter
        .read_kernel(registration, &mut registration_bytes[..registration_size])
        .map_err(|error| adapter_error("etw-ti-registration-read", error.code()))?;
    let guid_entry = read_u64(&registration_bytes, reg_guid).unwrap_or(0);

    if !is_kernel_pointer(guid_entry) || guid_entry & 7 != 0 {
        zero(&mut registration_bytes);
        return Err(etw_error("etw-ti-guid-pointer", 487));
    }

    let masks = [
        registration_bytes[reg_mask],
        registration_bytes[reg_mask + 1],
        registration_bytes[reg_mask + 2],
        registration_bytes[reg_mask + 3],
    ];
    zero(&mut registration_bytes);
    let mut guid = [0_u8; GUID_BYTES];
    adapter
        .read_kernel(guid_entry, &mut guid[..guid_size])
        .map_err(|error| adapter_error("etw-ti-guid-read", error.code()))?;
    let base = provider;
    let state = EtwTiState {
        registration,
        guid_entry,
        enable_mask: masks[0],
        group_enable_mask: masks[1],
        host_enable_mask: masks[2],
        host_group_enable_mask: masks[3],
        enabled: read_u32(&guid, base + enabled).unwrap_or(u32::MAX),
        level: guid[base + level],
        property: read_u32(&guid, base + property).unwrap_or(0),
        match_any: read_u64(&guid, base + match_any).unwrap_or(0),
        match_all: read_u64(&guid, base + match_all).unwrap_or(0),
    };
    zero(&mut guid);

    if state.enabled > 1 {
        return Err(etw_error("etw-ti-enabled-state", 13));
    }

    Ok(state)
}

fn enabled_address(profile: &KernelProfile, state: EtwTiState) -> Result<u64, EtwTiError> {
    state
        .guid_entry
        .checked_add(profile.value(KernelField::EtwGuidProviderEnableInfo) as u64)
        .and_then(|address| {
            address.checked_add(profile.value(KernelField::TraceEnableIsEnabled) as u64)
        })
        .filter(|address| is_kernel_pointer(*address))
        .ok_or_else(|| etw_error("etw-ti-enabled-address", 487))
}

fn restore_word<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    handle: u64,
    baseline: EtwTiState,
    original_enabled: u32,
) -> bool {
    let Ok(address) = enabled_address(profile, baseline) else {
        return false;
    };

    for _ in 0..3 {
        if adapter
            .write_kernel(address, &original_enabled.to_le_bytes())
            .is_ok()
            && read_state(adapter, profile, handle).is_ok_and(|after| {
                same_provider(baseline, after) && after.enabled == original_enabled
            })
        {
            return true;
        }
    }

    false
}

fn same_provider(left: EtwTiState, right: EtwTiState) -> bool {
    left.registration == right.registration
        && left.guid_entry == right.guid_entry
        && left.enable_mask == right.enable_mask
        && left.group_enable_mask == right.group_enable_mask
        && left.host_enable_mask == right.host_enable_mask
        && left.host_group_enable_mask == right.host_group_enable_mask
        && left.level == right.level
        && left.property == right.property
        && left.match_any == right.match_any
        && left.match_all == right.match_all
}

fn print_state(output: &mut Output, state: EtwTiState) {
    let _ = writeln!(
        output,
        "[*] Provider        : enabled={} level={} property=0x{:08x}",
        state.enabled, state.level, state.property
    );
    let _ = writeln!(
        output,
        "[*] Enable masks    : {:02x}/{:02x}/{:02x}/{:02x}",
        state.enable_mask,
        state.group_enable_mask,
        state.host_enable_mask,
        state.host_group_enable_mask
    );
    let _ = writeln!(
        output,
        "[*] Keywords       : any=0x{:016x} all=0x{:016x}",
        state.match_any, state.match_all
    );
}

impl EtwTiJournal {
    fn new(profile: &KernelProfile, original_enabled: u32) -> Self {
        Self {
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            original_enabled,
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
        write_u32(&mut output, 24, 1);
        write_u32(&mut output, 28, self.original_enabled);
        write_u32(&mut output, 32, 0);
        write_u64(&mut output, 40, JOURNAL_NONCE);
        let integrity = checksum(&output[..48]);
        write_u64(&mut output, 48, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u32(input, 24)? != 1
            || read_u32(input, 28)? != 1
            || read_u32(input, 32)? != 0
            || read_u64(input, 40)? != JOURNAL_NONCE
            || read_u64(input, 48)? != checksum(&input[..48])
        {
            return None;
        }

        Some(Self {
            kernel_timestamp: read_u32(input, 12)?,
            kernel_checksum: read_u32(input, 16)?,
            kernel_image_size: read_u32(input, 20)?,
            original_enabled: read_u32(input, 28)?,
        })
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
    }
}

const fn etw_error(stage: &'static str, code: u32) -> EtwTiError {
    EtwTiError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> EtwTiError {
    EtwTiError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn adapter_error(stage: &'static str, code: u32) -> EtwTiError {
    etw_error(stage, code)
}

const fn session_error(error: crate::session::SessionError) -> EtwTiError {
    EtwTiError {
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
) -> EtwTiError {
    EtwTiError {
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
    fn journal_round_trip_is_exact() {
        let journal = EtwTiJournal::new(&KERNEL_PROFILES[0], 1);

        assert_eq!(EtwTiJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = EtwTiJournal {
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            original_enabled: 1,
        }
        .encode();
        record[20] ^= 1;

        assert_eq!(EtwTiJournal::decode(&record), None);
    }
}
