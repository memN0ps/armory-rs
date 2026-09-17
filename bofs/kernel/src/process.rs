//! Handleless process discovery and security metadata inspection.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{ascii_eq_ignore_case, is_kernel_pointer, read_u16, read_u64, zero},
    output::Output,
    profiles::{KernelField, KernelProfile},
    session::KernelSession,
};
use core::fmt::Write;

const PROCESS_WINDOW_BYTES: usize = 0x400;
const IMAGE_PREFIX_BYTES: usize = 15;
const DISPLAY_NAME_BYTES: usize = 260;
const AUDIT_PATH_BYTES: usize = DISPLAY_NAME_BYTES * 2;
const MAX_PROCESS_WALK: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSelector {
    AuthenticationService,
    Current,
    Pid(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessError {
    Adapter(u32),
    InvalidProfile,
    InvalidRecord,
    NotFound,
}

impl ProcessError {
    pub(crate) const fn stage(self) -> &'static str {
        match self {
            Self::Adapter(_) => "process-read",
            Self::InvalidProfile => "process-profile",
            Self::InvalidRecord => "process-list",
            Self::NotFound => "process-not-found",
        }
    }

    pub(crate) const fn code(self) -> u32 {
        match self {
            Self::Adapter(code) => code,
            Self::InvalidProfile | Self::InvalidRecord => 13,
            Self::NotFound => 1168,
        }
    }
}

pub(crate) struct ProcessRecord {
    pub(crate) eprocess: u64,
    pub(crate) pid: u64,
    pub(crate) forward_link: u64,
    pub(crate) backward_link: u64,
    pub(crate) token_fast_ref: u64,
    pub(crate) directory_table_base: u64,
    pub(crate) section_base: u64,
    pub(crate) peb: u64,
    pub(crate) signature_level: u8,
    pub(crate) section_signature_level: u8,
    pub(crate) protection: u8,
    image_prefix: [u8; 16],
    image_name: [u8; DISPLAY_NAME_BYTES],
    image_name_from_audit: bool,
}

impl ProcessRecord {
    const fn empty() -> Self {
        Self {
            eprocess: 0,
            pid: 0,
            forward_link: 0,
            backward_link: 0,
            token_fast_ref: 0,
            directory_table_base: 0,
            section_base: 0,
            peb: 0,
            signature_level: 0,
            section_signature_level: 0,
            protection: 0,
            image_prefix: [0; 16],
            image_name: [0; DISPLAY_NAME_BYTES],
            image_name_from_audit: false,
        }
    }

    pub(crate) fn display_name(&self) -> &str {
        let length = self
            .image_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.image_name.len());

        core::str::from_utf8(&self.image_name[..length]).unwrap_or("unknown")
    }

    const fn protection_type(&self) -> &'static str {
        match self.protection & 7 {
            0 => "none",
            1 => "protected-light",
            2 => "protected",
            _ => "reserved",
        }
    }

    const fn protection_signer(&self) -> &'static str {
        match (self.protection >> 4) & 15 {
            0 => "none",
            1 => "authenticode",
            2 => "codegen",
            3 => "antimalware",
            4 => "lsa",
            5 => "windows",
            6 => "wintcb",
            7 => "winsystem",
            8 => "app",
            _ => "reserved",
        }
    }

    const fn protection_audit(&self) -> u8 {
        (self.protection >> 3) & 1
    }
}

pub fn inspect<A: KernelAdapter>(adapter: &mut A, selector: ProcessSelector, output: &mut Output) {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    output.line("[*] Inspecting process security state through kernel memory");
    let mut session = match KernelSession::open(adapter, REQUIRED, 0) {
        Ok(session) => session,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Process inspection failed at {} (0x{:08x}); cleanup={}",
                error.stage,
                error.code,
                complete_failed(error.cleanup_succeeded)
            );
            return;
        }
    };

    let target_pid = match selector {
        ProcessSelector::AuthenticationService => None,
        ProcessSelector::Current => Some(crate::platform::current_process_id()),
        ProcessSelector::Pid(pid) => Some(pid),
    };
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let result = find_process(session.adapter(), profile, system_process, target_pid);
    let succeeded = result.is_ok();

    match result {
        Ok((record, walked)) => print_record(output, profile, &record, walked),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Process inspection failed at {} (0x{:08x})",
                error.stage(),
                error.code()
            );
        }
    }

    if let Err(error) = session.close() {
        let _ = writeln!(
            output,
            "[-] Adapter close failed: {} (0x{:08x})",
            error.message(),
            error.code()
        );
        return;
    }

    if succeeded {
        output.line("[+] Process security inspection complete; OpenProcess was not used");
    }
}

pub(crate) fn find_process<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    system_process: u64,
    target_pid: Option<u32>,
) -> Result<(ProcessRecord, usize), ProcessError> {
    let mut current = system_process;

    for walked in 1..=MAX_PROCESS_WALK {
        let record = read_process_record(adapter, profile, current)?;
        let matched = match target_pid {
            Some(pid) => record.pid == pid as u64,
            None => ascii_eq_ignore_case(prefix_name(&record.image_prefix), b"lsass.exe"),
        };

        if matched {
            let mut record = record;
            let _ = read_audit_image_name(adapter, profile, &mut record);
            return Ok((record, walked));
        }

        let next = record
            .forward_link
            .checked_sub(profile.value(KernelField::EprocessLinks) as u64)
            .ok_or(ProcessError::InvalidRecord)?;

        if !is_kernel_pointer(next) {
            return Err(ProcessError::InvalidRecord);
        }

        if next == system_process {
            break;
        }

        current = next;
    }

    Err(ProcessError::NotFound)
}

pub(crate) fn read_process_record<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    eprocess: u64,
) -> Result<ProcessRecord, ProcessError> {
    if !is_kernel_pointer(eprocess) {
        return Err(ProcessError::InvalidRecord);
    }

    let start = profile.value(KernelField::EprocessPid) as usize;
    let links = relative_offset(profile, KernelField::EprocessLinks, start, 16)?;
    let token = relative_offset(profile, KernelField::EprocessToken, start, 8)?;
    let image = relative_offset(
        profile,
        KernelField::EprocessImage,
        start,
        IMAGE_PREFIX_BYTES,
    )?;
    let mut window = [0_u8; PROCESS_WINDOW_BYTES];
    adapter
        .read_kernel(eprocess + start as u64, &mut window)
        .map_err(|error| ProcessError::Adapter(error.code()))?;
    let mut record = ProcessRecord::empty();
    record.eprocess = eprocess;
    record.pid = read_u64(&window, 0).ok_or(ProcessError::InvalidRecord)?;
    record.forward_link = read_u64(&window, links).ok_or(ProcessError::InvalidRecord)?;
    record.backward_link = read_u64(&window, links + 8).ok_or(ProcessError::InvalidRecord)?;
    record.token_fast_ref = read_u64(&window, token).ok_or(ProcessError::InvalidRecord)?;
    record.image_prefix[..IMAGE_PREFIX_BYTES]
        .copy_from_slice(&window[image..image + IMAGE_PREFIX_BYTES]);
    set_fallback_name(&mut record);
    zero(&mut window);

    record.directory_table_base = read_u64_at(
        adapter,
        eprocess
            + profile.value(KernelField::EprocessPcb) as u64
            + profile.value(KernelField::KprocessDirectoryTableBase) as u64,
    )?;
    record.section_base = read_u64_at(
        adapter,
        eprocess + profile.value(KernelField::EprocessSectionBase) as u64,
    )?;
    record.peb = read_u64_at(
        adapter,
        eprocess + profile.value(KernelField::EprocessPeb) as u64,
    )?;
    record.signature_level = read_u8_at(
        adapter,
        eprocess + profile.value(KernelField::EprocessSignatureLevel) as u64,
    )?;
    record.section_signature_level = read_u8_at(
        adapter,
        eprocess + profile.value(KernelField::EprocessSectionSignatureLevel) as u64,
    )?;
    record.protection = read_u8_at(
        adapter,
        eprocess + profile.value(KernelField::EprocessProtection) as u64,
    )?;

    if !is_kernel_pointer(record.forward_link)
        || !is_kernel_pointer(record.backward_link)
        || !valid_optional_fast_ref(record.token_fast_ref)
    {
        return Err(ProcessError::InvalidRecord);
    }

    Ok(record)
}

const fn valid_optional_fast_ref(value: u64) -> bool {
    value == 0 || is_kernel_pointer(value & !15)
}

pub(crate) fn same_kernel_state(left: &ProcessRecord, right: &ProcessRecord) -> bool {
    left.eprocess == right.eprocess
        && left.pid == right.pid
        && left.forward_link == right.forward_link
        && left.backward_link == right.backward_link
        && left.token_fast_ref == right.token_fast_ref
        && left.directory_table_base == right.directory_table_base
        && left.section_base == right.section_base
        && left.peb == right.peb
        && left.signature_level == right.signature_level
        && left.section_signature_level == right.section_signature_level
        && left.protection == right.protection
        && left.image_prefix == right.image_prefix
}

fn relative_offset(
    profile: &KernelProfile,
    field: KernelField,
    start: usize,
    required: usize,
) -> Result<usize, ProcessError> {
    let absolute = profile.value(field) as usize;
    let relative = absolute
        .checked_sub(start)
        .ok_or(ProcessError::InvalidProfile)?;

    if relative
        .checked_add(required)
        .is_none_or(|end| end > PROCESS_WINDOW_BYTES)
    {
        return Err(ProcessError::InvalidProfile);
    }

    Ok(relative)
}

fn read_u64_at<A: KernelAdapter>(adapter: &mut A, address: u64) -> Result<u64, ProcessError> {
    let mut bytes = [0_u8; 8];
    adapter
        .read_kernel(address, &mut bytes)
        .map_err(|error| ProcessError::Adapter(error.code()))?;
    let value = read_u64(&bytes, 0).ok_or(ProcessError::InvalidRecord)?;
    zero(&mut bytes);

    Ok(value)
}

fn read_u8_at<A: KernelAdapter>(adapter: &mut A, address: u64) -> Result<u8, ProcessError> {
    let mut value = [0_u8; 1];
    adapter
        .read_kernel(address, &mut value)
        .map_err(|error| ProcessError::Adapter(error.code()))?;

    Ok(value[0])
}

fn read_audit_image_name<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    record: &mut ProcessRecord,
) -> Result<(), ProcessError> {
    let name_information = read_u64_at(
        adapter,
        record.eprocess + profile.value(KernelField::EprocessAuditImage) as u64,
    )?;

    if !is_kernel_pointer(name_information) {
        return Err(ProcessError::InvalidRecord);
    }

    let mut header = [0_u8; 16];
    adapter
        .read_kernel(name_information, &mut header)
        .map_err(|error| ProcessError::Adapter(error.code()))?;
    let length = read_u16(&header, 0).ok_or(ProcessError::InvalidRecord)? as usize;
    let maximum = read_u16(&header, 2).ok_or(ProcessError::InvalidRecord)? as usize;
    let path = read_u64(&header, 8).ok_or(ProcessError::InvalidRecord)?;
    zero(&mut header);

    if length == 0 || length & 1 != 0 || length > maximum || !is_kernel_pointer(path) {
        return Err(ProcessError::InvalidRecord);
    }

    let read_bytes = length.min(AUDIT_PATH_BYTES - 2);
    let read_address = path
        .checked_add((length - read_bytes) as u64)
        .ok_or(ProcessError::InvalidRecord)?;
    let mut wide_path = [0_u8; AUDIT_PATH_BYTES];
    adapter
        .read_kernel(read_address, &mut wide_path[..read_bytes])
        .map_err(|error| ProcessError::Adapter(error.code()))?;
    let mut output_index = 0;

    for pair in wide_path[..read_bytes].chunks_exact(2) {
        let low = pair[0];
        let high = pair[1];

        if low == 0 && high == 0 {
            break;
        }

        if high == 0 && (low == b'\\' || low == b'/') {
            output_index = 0;
            continue;
        }

        if output_index + 1 >= record.image_name.len() {
            break;
        }

        record.image_name[output_index] = if high == 0 && (0x20..=0x7e).contains(&low) {
            low
        } else {
            b'?'
        };
        output_index += 1;
    }

    zero(&mut wide_path);

    if output_index == 0 {
        return Err(ProcessError::InvalidRecord);
    }

    record.image_name[output_index] = 0;
    record.image_name_from_audit = true;

    Ok(())
}

fn set_fallback_name(record: &mut ProcessRecord) {
    for (index, byte) in record
        .image_prefix
        .iter()
        .copied()
        .take(IMAGE_PREFIX_BYTES)
        .enumerate()
    {
        if byte == 0 {
            break;
        }

        record.image_name[index] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
    }
}

fn prefix_name(prefix: &[u8; 16]) -> &[u8] {
    let length = prefix
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(prefix.len());

    &prefix[..length]
}

fn print_record(
    output: &mut Output,
    profile: &KernelProfile,
    record: &ProcessRecord,
    walked: usize,
) {
    let _ = writeln!(
        output,
        "[*] Kernel profile  : {} exact PE and PDB match",
        profile.display_build
    );
    let _ = writeln!(
        output,
        "[*] Process         : pid={} image={} name-source={} walked={}",
        record.pid,
        record.display_name(),
        if record.image_name_from_audit {
            "audit-path"
        } else {
            "kernel-prefix"
        },
        walked
    );
    let _ = writeln!(
        output,
        "[*] Protection      : type={} signer={} audit={}",
        record.protection_type(),
        record.protection_signer(),
        record.protection_audit()
    );
    let _ = writeln!(
        output,
        "[*] Signature       : image=0x{:02x} section=0x{:02x}",
        record.signature_level, record.section_signature_level
    );
    let _ = writeln!(
        output,
        "[*] Metadata        : token={} refbits={} dtb={} peb={} section={}",
        present(record.token_fast_ref & !15 != 0),
        record.token_fast_ref & 15,
        present(record.directory_table_base != 0),
        present(record.peb != 0),
        present(record.section_base != 0)
    );
}

const fn present(value: bool) -> &'static str {
    if value { "present" } else { "absent" }
}

const fn complete_failed(value: bool) -> &'static str {
    if value { "complete" } else { "failed" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_process_protection() {
        let mut record = ProcessRecord::empty();
        record.protection = 0x41;

        assert_eq!(record.protection_type(), "protected-light");
        assert_eq!(record.protection_signer(), "lsa");
        assert_eq!(record.protection_audit(), 0);
    }

    #[test]
    fn accepts_only_zero_or_canonical_token_fast_references() {
        assert!(valid_optional_fast_ref(0));
        assert!(valid_optional_fast_ref(0xffff_8000_0000_0005));
        assert!(!valid_optional_fast_ref(5));
        assert!(!valid_optional_fast_ref(0x1005));
    }

    #[test]
    fn keeps_full_fallback_prefix() {
        let mut record = ProcessRecord::empty();
        record.image_prefix[..15].copy_from_slice(b"example_process");
        set_fallback_name(&mut record);

        assert_eq!(record.display_name(), "example_process");
    }
}
