//! Handleless user-module discovery through a target process PFN snapshot.

use crate::{
    adapter::KernelAdapter,
    bytes::{ascii_eq_ignore_case, read_u16, read_u32, read_u64, zero},
    kernel::ImageIdentity,
    system_image::{SystemImage, SystemImageError},
    virtual_memory::{ProcessMemory, VirtualMemoryError, valid_user_address},
};

const MAX_MODULE_WALK: usize = 256;
const MAX_NAME_BYTES: usize = 520;
const LDR_ENTRY_BYTES: usize = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserModule {
    pub base: u64,
    pub size: u32,
    pub identity: ImageIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserModuleError {
    InvalidPeb,
    InvalidLoader,
    InvalidList,
    InvalidEntry,
    InvalidName,
    InvalidImage,
    NotFound,
    NotUnique,
    Memory(VirtualMemoryError),
    SystemImage(SystemImageError),
}

impl UserModuleError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::InvalidPeb => "user-module-peb",
            Self::InvalidLoader => "user-module-loader",
            Self::InvalidList => "user-module-list",
            Self::InvalidEntry => "user-module-entry",
            Self::InvalidName => "user-module-name",
            Self::InvalidImage => "user-module-image",
            Self::NotFound => "user-module-not-found",
            Self::NotUnique => "user-module-not-unique",
            Self::Memory(error) => error.stage(),
            Self::SystemImage(error) => error.stage(),
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::Memory(error) => error.code(),
            Self::SystemImage(error) => error.code(),
            Self::NotFound => 1168,
            Self::NotUnique
            | Self::InvalidPeb
            | Self::InvalidLoader
            | Self::InvalidList
            | Self::InvalidEntry
            | Self::InvalidName
            | Self::InvalidImage => 13,
        }
    }
}

pub fn find_module<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    peb: u64,
    expected: &[u8],
) -> Result<(UserModule, usize), UserModuleError> {
    if !valid_user_address(peb) || expected.is_empty() || expected.len() > MAX_NAME_BYTES / 2 {
        return Err(UserModuleError::InvalidPeb);
    }

    let image_base = memory
        .read_u64(peb + 0x10)
        .map_err(UserModuleError::Memory)?;
    let ldr = memory
        .read_u64(peb + 0x18)
        .map_err(UserModuleError::Memory)?;

    if !valid_user_address(image_base) || image_base & 0xfff != 0 || !valid_user_address(ldr) {
        return Err(UserModuleError::InvalidLoader);
    }

    let ldr_length = memory.read_u32(ldr).map_err(UserModuleError::Memory)?;
    let head = ldr.checked_add(0x20).ok_or(UserModuleError::InvalidList)?;
    let mut current = memory.read_u64(head).map_err(UserModuleError::Memory)?;

    if ldr_length == 0 || ldr_length > 0x400 || !valid_user_address(current) {
        return Err(UserModuleError::InvalidList);
    }

    let mut found = None;
    let mut walked = 0;
    let mut previous = head;

    while current != head && walked < MAX_MODULE_WALK {
        if !valid_user_address(current) || current & 7 != 0 {
            return Err(UserModuleError::InvalidList);
        }

        let entry_address = current
            .checked_sub(0x10)
            .ok_or(UserModuleError::InvalidEntry)?;
        let mut entry = [0_u8; LDR_ENTRY_BYTES];
        memory
            .read(entry_address, &mut entry)
            .map_err(UserModuleError::Memory)?;
        let next = read_u64(&entry, 0x10).ok_or(UserModuleError::InvalidEntry)?;
        let back = read_u64(&entry, 0x18).ok_or(UserModuleError::InvalidEntry)?;
        let base = read_u64(&entry, 0x30).ok_or(UserModuleError::InvalidEntry)?;
        let size = read_u32(&entry, 0x40).ok_or(UserModuleError::InvalidEntry)?;
        let name_length = read_u16(&entry, 0x58).ok_or(UserModuleError::InvalidName)? as usize;
        let name_maximum = read_u16(&entry, 0x5a).ok_or(UserModuleError::InvalidName)? as usize;
        let name_pointer = read_u64(&entry, 0x60).ok_or(UserModuleError::InvalidName)?;

        if back != previous
            || !valid_user_address(next)
            || !valid_user_address(base)
            || base & 0xfff != 0
            || size == 0
            || name_length & 1 != 0
            || name_length > name_maximum
            || name_length > MAX_NAME_BYTES
            || (name_length != 0 && !valid_user_address(name_pointer))
        {
            zero(&mut entry);
            return Err(UserModuleError::InvalidEntry);
        }

        if name_length != 0 {
            let mut name = [0_u8; MAX_NAME_BYTES];
            memory
                .read(name_pointer, &mut name[..name_length])
                .map_err(UserModuleError::Memory)?;

            if wide_name_matches(&name[..name_length], expected) {
                if found.is_some() {
                    zero(&mut name);
                    zero(&mut entry);
                    return Err(UserModuleError::NotUnique);
                }

                let system_image =
                    SystemImage::open(expected).map_err(UserModuleError::SystemImage)?;
                let identity = system_image.identity();

                if identity.image_size != size {
                    zero(&mut name);
                    zero(&mut entry);
                    return Err(UserModuleError::InvalidImage);
                }

                found = Some(UserModule {
                    base,
                    size,
                    identity,
                });
            }

            zero(&mut name);
        }

        zero(&mut entry);
        previous = current;
        current = next;
        walked += 1;
    }

    if current != head {
        return Err(UserModuleError::InvalidList);
    }

    found
        .map(|module| (module, walked))
        .ok_or(UserModuleError::NotFound)
}

fn wide_name_matches(input: &[u8], expected: &[u8]) -> bool {
    if input.len() != expected.len() * 2 {
        return false;
    }

    let mut decoded = [0_u8; MAX_NAME_BYTES / 2];

    for (index, output) in decoded[..expected.len()].iter_mut().enumerate() {
        let Some(character) = read_u16(input, index * 2) else {
            return false;
        };

        if character > 0x7f {
            return false;
        }

        *output = character as u8;
    }

    ascii_eq_ignore_case(&decoded[..expected.len()], expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ascii_wide_names_without_case() {
        let mut input = [0_u8; 22];

        for (index, byte) in b"WDIGEST.DLL".iter().enumerate() {
            input[index * 2] = *byte;
        }

        assert!(wide_name_matches(&input, b"wdigest.dll"));
        assert!(!wide_name_matches(&input, b"lsasrv.dll"));
    }
}
