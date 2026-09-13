//! Exact selected-process protection metadata cycle and recovery.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{read_u32, read_u64, write_u32, write_u64, zero},
    output::Output,
    platform::current_process_id,
    process::{ProcessRecord, ProcessSelector, find_process, read_process_record},
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
    token::read_state,
};
use core::fmt::Write;

const JOURNAL_BYTES: usize = 72;
const JOURNAL_MAGIC: u32 = 0x4350_524b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3143_5052_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 56, 65, 52, 51, 46, 116, 109, 112, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionAction {
    Cycle {
        selector: ProcessSelector,
        expected: u8,
        changed: u8,
    },
    Restore(ProcessSelector),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectionJournal {
    target_pid: u32,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    field_offset: u32,
    section_base: u64,
    token_id: u64,
    original: [u8; 3],
    changed: [u8; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectionError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: ProtectionAction, output: &mut Output) {
    let result = match action {
        ProtectionAction::Cycle {
            selector,
            expected,
            changed,
        } => cycle(adapter, selector, expected, changed, output),
        ProtectionAction::Restore(selector) => restore(adapter, selector, output),
    };

    match result {
        Ok(()) => output.line(match action {
            ProtectionAction::Cycle { .. } => {
                "[+] Process protection cycle complete; original metadata restored"
            }
            ProtectionAction::Restore(_) => {
                "[+] Process protection recovery complete; original metadata restored"
            }
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Process protection action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn cycle<A: KernelAdapter>(
    adapter: &mut A,
    selector: ProcessSelector,
    expected: u8,
    changed: u8,
    output: &mut Output,
) -> Result<(), ProtectionError> {
    if !valid_protection(expected) || !valid_protection(changed) || expected == changed {
        return Err(protection_error("protection-arguments", 87));
    }

    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    output.line("[*] Cycling one process protection tuple");
    let mut session = KernelSession::open(adapter, REQUIRED, 1).map_err(session_error)?;
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let (before, walked) = find_process(
        session.adapter(),
        profile,
        system_process,
        selector_pid(selector),
    )
    .map_err(process_error)?;
    let confirmed =
        read_process_record(session.adapter(), profile, before.eprocess).map_err(process_error)?;
    let token =
        read_state(session.adapter(), profile, before.token_fast_ref & !15).map_err(token_error)?;

    if !same_target(&before, &confirmed) || before.protection != expected || token.token_type != 1 {
        return Err(protection_error("protection-exact-original-state", 13));
    }

    let changed_tuple = [
        before.signature_level,
        before.section_signature_level,
        changed,
    ];
    let journal = ProtectionJournal::new(profile, &before, token.token_id, changed_tuple);
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let address = before
        .eprocess
        .checked_add(profile.value(KernelField::EprocessProtection) as u64)
        .ok_or_else(|| protection_error("protection-field-address", 487))?;
    let write_result = session.adapter().write_kernel(address, &[changed]);
    let after = read_process_record(session.adapter(), profile, before.eprocess);
    let changed_valid = write_result.is_ok()
        && after
            .as_ref()
            .is_ok_and(|after| exact_state(&before, after, changed_tuple));

    if !changed_valid {
        let rollback = restore_value(session.adapter(), profile, &before, journal.original);

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        zero(&mut record);
        return Err(ProtectionError {
            stage: "protection-change-readback",
            code: write_result
                .err()
                .map(|error| error.code())
                .or_else(|| after.err().map(|error| error.code()))
                .unwrap_or(13),
            rollback,
            recovery_retained: !rollback,
        });
    }

    let _ = writeln!(
        output,
        "[*] Target          : pid={} image={} walked={}",
        before.pid,
        before.display_name(),
        walked
    );
    let _ = writeln!(
        output,
        "[*] Protection      : 0x{:02x} -> 0x{:02x}; one-byte write verified",
        expected, changed
    );

    if !restore_value(session.adapter(), profile, &before, journal.original) {
        zero(&mut record);
        return Err(ProtectionError {
            stage: "protection-cycle-restore",
            code: 13,
            rollback: false,
            recovery_retained: true,
        });
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    zero(&mut record);
    session.close().map_err(|error| ProtectionError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original signature, section-signature, and protection tuple restored");

    Ok(())
}

fn restore<A: KernelAdapter>(
    adapter: &mut A,
    selector: ProcessSelector,
    output: &mut Output,
) -> Result<(), ProtectionError> {
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = ProtectionJournal::decode(&record)
        .ok_or_else(|| retained_error("protection-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 1).map_err(session_error)?;
    let profile = session.kernel.profile;

    if !selector_matches_pid(selector, journal.target_pid) {
        return Err(retained_error("protection-recovery-profile", 13));
    }

    let system_process = session.system_process;
    let current = match find_process(
        session.adapter(),
        profile,
        system_process,
        Some(journal.target_pid),
    ) {
        Ok((current, _)) => current,
        Err(crate::process::ProcessError::NotFound) => {
            RecoveryStore::delete(RECOVERY_NAME)
                .map_err(|error| recovery_error(error, true, true))?;
            session.close().map_err(|error| ProtectionError {
                stage: "adapter-close",
                code: error.code(),
                rollback: true,
                recovery_retained: false,
            })?;
            output.line("[*] Target process has exited; stale recovery record removed");

            return Ok(());
        }
        Err(error) => return Err(process_error(error)),
    };

    if !journal.matches_profile(profile) {
        return Err(retained_error("protection-recovery-profile", 13));
    }

    let token = read_state(session.adapter(), profile, current.token_fast_ref & !15)
        .map_err(token_error)?;

    if current.section_base != journal.section_base || token.token_id != journal.token_id {
        return Err(retained_error("protection-recovery-target", 13));
    }

    let tuple = state_tuple(&current);

    if tuple == journal.changed {
        if !restore_value(session.adapter(), profile, &current, journal.original) {
            return Err(retained_error("protection-restore-readback", 13));
        }
    } else if tuple != journal.original {
        return Err(retained_error("protection-unexpected-live-state", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(|error| ProtectionError {
        stage: "adapter-close",
        code: error.code(),
        rollback: true,
        recovery_retained: false,
    })?;
    output.line("[*] Original process protection tuple was verified");

    Ok(())
}

fn restore_value<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    before: &ProcessRecord,
    tuple: [u8; 3],
) -> bool {
    let address = before.eprocess + profile.value(KernelField::EprocessProtection) as u64;

    for _ in 0..3 {
        if adapter.write_kernel(address, &tuple[2..3]).is_ok()
            && read_process_record(adapter, profile, before.eprocess)
                .is_ok_and(|after| exact_state(before, &after, tuple))
        {
            return true;
        }
    }

    false
}

fn exact_state(before: &ProcessRecord, after: &ProcessRecord, tuple: [u8; 3]) -> bool {
    same_target(before, after) && state_tuple(after) == tuple
}

fn same_target(left: &ProcessRecord, right: &ProcessRecord) -> bool {
    left.eprocess == right.eprocess
        && left.pid == right.pid
        && left.section_base == right.section_base
        && same_token_object(left.token_fast_ref, right.token_fast_ref)
}

const fn same_token_object(left: u64, right: u64) -> bool {
    left & !15 == right & !15
}

const fn state_tuple(process: &ProcessRecord) -> [u8; 3] {
    [
        process.signature_level,
        process.section_signature_level,
        process.protection,
    ]
}

const fn valid_protection(value: u8) -> bool {
    (value & 7) <= 2 && (value >> 4) <= 8
}

fn selector_pid(selector: ProcessSelector) -> Option<u32> {
    match selector {
        ProcessSelector::AuthenticationService => None,
        ProcessSelector::Current => Some(current_process_id()),
        ProcessSelector::Pid(pid) => Some(pid),
    }
}

fn selector_matches_pid(selector: ProcessSelector, pid: u32) -> bool {
    match selector {
        ProcessSelector::AuthenticationService => true,
        ProcessSelector::Current => current_process_id() == pid,
        ProcessSelector::Pid(selected) => selected == pid,
    }
}

impl ProtectionJournal {
    fn new(
        profile: &KernelProfile,
        target: &ProcessRecord,
        token_id: u64,
        changed: [u8; 3],
    ) -> Self {
        Self {
            target_pid: target.pid as u32,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            field_offset: profile.value(KernelField::EprocessProtection),
            section_base: target.section_base,
            token_id,
            original: state_tuple(target),
            changed,
        }
    }

    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.target_pid);
        write_u32(&mut output, 16, self.kernel_timestamp);
        write_u32(&mut output, 20, self.kernel_checksum);
        write_u32(&mut output, 24, self.kernel_image_size);
        write_u32(&mut output, 28, self.field_offset);
        write_u64(&mut output, 32, self.section_base);
        write_u64(&mut output, 40, self.token_id);
        output[48..51].copy_from_slice(&self.original);
        output[51..54].copy_from_slice(&self.changed);
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
            target_pid: read_u32(input, 12)?,
            kernel_timestamp: read_u32(input, 16)?,
            kernel_checksum: read_u32(input, 20)?,
            kernel_image_size: read_u32(input, 24)?,
            field_offset: read_u32(input, 28)?,
            section_base: read_u64(input, 32)?,
            token_id: read_u64(input, 40)?,
            original: [input[48], input[49], input[50]],
            changed: [input[51], input[52], input[53]],
        };

        if journal.target_pid <= 4
            || journal.section_base == 0
            || journal.token_id == 0
            || !valid_protection(journal.original[2])
            || !valid_protection(journal.changed[2])
            || journal.original[2] == journal.changed[2]
        {
            return None;
        }

        Some(journal)
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
            && self.field_offset == profile.value(KernelField::EprocessProtection)
    }
}

const fn protection_error(stage: &'static str, code: u32) -> ProtectionError {
    ProtectionError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> ProtectionError {
    ProtectionError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn session_error(error: crate::session::SessionError) -> ProtectionError {
    ProtectionError {
        stage: error.stage,
        code: error.code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn process_error(error: crate::process::ProcessError) -> ProtectionError {
    protection_error(error.stage(), error.code())
}

const fn token_error(error: crate::token::TokenError) -> ProtectionError {
    protection_error(error.stage(), error.code())
}

const fn recovery_error(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> ProtectionError {
    ProtectionError {
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
    fn accepts_valid_protection_values() {
        assert!(valid_protection(0x00));
        assert!(valid_protection(0x41));
        assert!(!valid_protection(0x03));
        assert!(!valid_protection(0xf1));
    }

    #[test]
    fn ignores_transient_fast_reference_bits_for_target_identity() {
        assert!(same_token_object(
            0xffff_8000_1234_5001,
            0xffff_8000_1234_500f
        ));
        assert!(!same_token_object(
            0xffff_8000_1234_5001,
            0xffff_8000_1234_5011
        ));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = ProtectionJournal {
            target_pid: 100,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            field_offset: 4,
            section_base: 5,
            token_id: 6,
            original: [0x3c, 8, 0x41],
            changed: [0x3c, 8, 0],
        }
        .encode();
        record[24] ^= 1;

        assert_eq!(ProtectionJournal::decode(&record), None);
    }
}
