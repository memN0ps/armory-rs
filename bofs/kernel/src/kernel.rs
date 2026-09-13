//! Exact loaded-kernel identity and profile verification.

use crate::{
    adapter::{AdapterError, KernelAdapter},
    bytes::{is_kernel_pointer, read_u16, read_u32, zero},
    modules::SystemModules,
    profiles::{KernelField, KernelProfile, find_kernel_profile},
};

pub const KERNEL_HEADER_BYTES: usize = 2048;
const MAX_DEBUG_DIRECTORY_BYTES: usize = 1024;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const DEBUG_TYPE_CODEVIEW: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelError {
    ModuleNotFound,
    InvalidBase,
    HeaderRead(AdapterError),
    InvalidImage,
    ProfileNotFound,
    ModuleSizeMismatch,
    DebugDirectory,
    CodeViewRead(AdapterError),
    CodeViewMismatch,
}

impl KernelError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::ModuleNotFound => "kernel-module",
            Self::InvalidBase => "kernel-module-base",
            Self::HeaderRead(_) => "kernel-header-read",
            Self::InvalidImage => "kernel-image",
            Self::ProfileNotFound => "kernel-profile",
            Self::ModuleSizeMismatch => "kernel-module-size",
            Self::DebugDirectory => "kernel-debug-directory",
            Self::CodeViewRead(_) => "kernel-codeview-read",
            Self::CodeViewMismatch => "kernel-codeview-identity",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::HeaderRead(error) | Self::CodeViewRead(error) => error.code(),
            Self::ModuleNotFound => 126,
            Self::InvalidBase => 487,
            Self::InvalidImage | Self::DebugDirectory => 193,
            Self::ProfileNotFound | Self::ModuleSizeMismatch | Self::CodeViewMismatch => 1306,
        }
    }
}

#[derive(Clone, Copy)]
pub struct KernelContext {
    pub base: u64,
    pub profile: &'static KernelProfile,
}

pub fn verify_loaded_kernel<A: KernelAdapter>(
    adapter: &mut A,
    modules: &SystemModules,
) -> Result<KernelContext, KernelError> {
    let module = modules
        .find(b"ntoskrnl.exe")
        .ok_or(KernelError::ModuleNotFound)?;
    let base = module.base();

    if !is_kernel_pointer(base) {
        return Err(KernelError::InvalidBase);
    }

    let mut headers = [0_u8; KERNEL_HEADER_BYTES];
    adapter
        .read_kernel(base, &mut headers)
        .map_err(KernelError::HeaderRead)?;
    let identity = parse_image_identity(&headers).ok_or(KernelError::InvalidImage)?;
    let profile = find_kernel_profile(identity.timestamp, identity.checksum, identity.image_size)
        .ok_or(KernelError::ProfileNotFound)?;

    if module.image_size() != profile.value(KernelField::ImageSize) {
        zero(&mut headers);
        return Err(KernelError::ModuleSizeMismatch);
    }

    let codeview_result = verify_codeview(adapter, base, &headers, profile);
    zero(&mut headers);
    codeview_result?;

    Ok(KernelContext { base, profile })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImageIdentity {
    pub(crate) timestamp: u32,
    pub(crate) checksum: u32,
    pub(crate) image_size: u32,
}

pub(crate) fn parse_image_identity(headers: &[u8]) -> Option<ImageIdentity> {
    if read_u16(headers, 0)? != 0x5a4d {
        return None;
    }

    let nt = read_u32(headers, 0x3c)? as usize;

    if read_u32(headers, nt)? != 0x0000_4550
        || read_u16(headers, nt.checked_add(4)?)? != 0x8664
        || read_u16(headers, nt.checked_add(24)?)? != 0x020b
    {
        return None;
    }

    Some(ImageIdentity {
        timestamp: read_u32(headers, nt.checked_add(8)?)?,
        image_size: read_u32(headers, nt.checked_add(24 + 0x38)?)?,
        checksum: read_u32(headers, nt.checked_add(24 + 0x40)?)?,
    })
}

fn verify_codeview<A: KernelAdapter>(
    adapter: &mut A,
    kernel_base: u64,
    headers: &[u8],
    profile: &KernelProfile,
) -> Result<(), KernelError> {
    let nt = read_u32(headers, 0x3c).ok_or(KernelError::DebugDirectory)? as usize;
    let optional = nt.checked_add(24).ok_or(KernelError::DebugDirectory)?;
    let optional_size = read_u16(headers, nt + 20).ok_or(KernelError::DebugDirectory)? as usize;
    let directory_count =
        read_u32(headers, optional + 0x6c).ok_or(KernelError::DebugDirectory)? as usize;

    if optional
        .checked_add(optional_size)
        .is_none_or(|end| end > headers.len())
        || optional_size < 0x70 + ((DEBUG_DIRECTORY_INDEX + 1) * 8)
        || directory_count <= DEBUG_DIRECTORY_INDEX
    {
        return Err(KernelError::DebugDirectory);
    }

    let directory_entry = optional + 0x70 + (DEBUG_DIRECTORY_INDEX * 8);
    let directory_rva = read_u32(headers, directory_entry).ok_or(KernelError::DebugDirectory)?;
    let directory_size =
        read_u32(headers, directory_entry + 4).ok_or(KernelError::DebugDirectory)? as usize;
    let image_size = profile.value(KernelField::ImageSize) as usize;

    if directory_rva == 0
        || !(28..=MAX_DEBUG_DIRECTORY_BYTES).contains(&directory_size)
        || (directory_rva as usize)
            .checked_add(directory_size)
            .is_none_or(|end| end > image_size)
    {
        return Err(KernelError::DebugDirectory);
    }

    let mut directory = [0_u8; MAX_DEBUG_DIRECTORY_BYTES];
    adapter
        .read_kernel(
            kernel_base + directory_rva as u64,
            &mut directory[..directory_size],
        )
        .map_err(KernelError::CodeViewRead)?;
    let mut record = [0_u8; 24];
    let mut matches = 0_u32;

    for entry in directory[..directory_size].as_chunks::<28>().0 {
        let Some(kind) = read_u32(entry, 12) else {
            continue;
        };
        let Some(data_size) = read_u32(entry, 16) else {
            continue;
        };
        let Some(data_rva) = read_u32(entry, 20) else {
            continue;
        };

        if kind != DEBUG_TYPE_CODEVIEW
            || data_size < record.len() as u32
            || data_rva == 0
            || (data_rva as usize)
                .checked_add(record.len())
                .is_none_or(|end| end > image_size)
        {
            continue;
        }

        zero(&mut record);
        adapter
            .read_kernel(kernel_base + data_rva as u64, &mut record)
            .map_err(KernelError::CodeViewRead)?;

        if codeview_matches(&record, profile) {
            matches += 1;
        }
    }

    zero(&mut directory);
    zero(&mut record);

    if matches != 1 {
        return Err(KernelError::CodeViewMismatch);
    }

    Ok(())
}

fn codeview_matches(record: &[u8], profile: &KernelProfile) -> bool {
    read_u32(record, 0) == Some(0x5344_5352)
        && read_u32(record, 4) == Some(profile.value(KernelField::PdbGuidA))
        && read_u16(record, 8) == Some(profile.value(KernelField::PdbGuidB) as u16)
        && read_u16(record, 10) == Some(profile.value(KernelField::PdbGuidC) as u16)
        && read_u32(record, 12) == Some(profile.value(KernelField::PdbGuidDLow))
        && read_u32(record, 16) == Some(profile.value(KernelField::PdbGuidDHigh))
        && read_u32(record, 20) == Some(profile.value(KernelField::PdbAge))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_amd64_pe_identity() {
        let mut headers = [0_u8; KERNEL_HEADER_BYTES];
        headers[0..2].copy_from_slice(&0x5a4d_u16.to_le_bytes());
        headers[0x3c..0x40].copy_from_slice(&0x100_u32.to_le_bytes());
        headers[0x100..0x104].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        headers[0x104..0x106].copy_from_slice(&0x8664_u16.to_le_bytes());
        headers[0x118..0x11a].copy_from_slice(&0x020b_u16.to_le_bytes());
        headers[0x108..0x10c].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        headers[0x150..0x154].copy_from_slice(&0x00c0_0000_u32.to_le_bytes());
        headers[0x158..0x15c].copy_from_slice(&0x000a_bcde_u32.to_le_bytes());

        assert_eq!(
            parse_image_identity(&headers),
            Some(ImageIdentity {
                timestamp: 0x1234_5678,
                checksum: 0x000a_bcde,
                image_size: 0x00c0_0000,
            })
        );
    }

    #[test]
    fn rejects_non_amd64_image() {
        let mut headers = [0_u8; KERNEL_HEADER_BYTES];
        headers[0..2].copy_from_slice(&0x5a4d_u16.to_le_bytes());
        headers[0x3c..0x40].copy_from_slice(&0x100_u32.to_le_bytes());
        headers[0x100..0x104].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        headers[0x104..0x106].copy_from_slice(&0x014c_u16.to_le_bytes());
        headers[0x118..0x11a].copy_from_slice(&0x010b_u16.to_le_bytes());

        assert_eq!(parse_image_identity(&headers), None);
    }
}
