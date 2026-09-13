//! Bounded loaded-kernel-module discovery through NtQuerySystemInformation.

use crate::bytes::ascii_eq_ignore_case;
use core::{ffi::c_void, mem::size_of, ptr::NonNull, slice};

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const MAX_MODULE_BUFFER: usize = 2 * 1024 * 1024;
const MAX_MODULES: usize = 4096;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleError {
    Query(i32),
    Allocation,
    InvalidLength,
    InvalidCount,
}

impl ModuleError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::Query(_) => "module-query",
            Self::Allocation => "module-allocation",
            Self::InvalidLength => "module-buffer-length",
            Self::InvalidCount => "module-count",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::Query(status) => status as u32,
            Self::Allocation => 8,
            Self::InvalidLength | Self::InvalidCount => 13,
        }
    }
}

#[repr(C)]
pub struct ModuleEntry {
    section: *mut c_void,
    mapped_base: *mut c_void,
    image_base: *mut c_void,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    offset_to_file_name: u16,
    full_path_name: [u8; 256],
}

impl ModuleEntry {
    pub fn base(&self) -> u64 {
        self.image_base as usize as u64
    }

    pub const fn image_size(&self) -> u32 {
        self.image_size
    }

    pub fn basename(&self) -> Option<&[u8]> {
        let start = self.offset_to_file_name as usize;
        let value = self.full_path_name.get(start..)?;
        let end = value.iter().position(|byte| *byte == 0)?;

        value.get(..end)
    }

    pub fn contains(&self, address: u64) -> bool {
        let base = self.base();
        let Some(end) = base.checked_add(self.image_size as u64) else {
            return false;
        };

        address >= base && address < end
    }
}

pub struct SystemModules {
    allocation: NonNull<u8>,
    allocation_size: usize,
    entries: NonNull<ModuleEntry>,
    count: usize,
}

impl SystemModules {
    pub fn query() -> Result<Self, ModuleError> {
        query_modules()
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub fn find(&self, expected: &[u8]) -> Option<&ModuleEntry> {
        self.entries().iter().find(|entry| {
            entry
                .basename()
                .is_some_and(|name| ascii_eq_ignore_case(name, expected))
        })
    }

    pub fn owner(&self, address: u64) -> Option<&ModuleEntry> {
        self.entries().iter().find(|entry| entry.contains(address))
    }

    fn entries(&self) -> &[ModuleEntry] {
        // SAFETY: `entries` points inside the owned allocation. `count` was
        // bounded and the complete array size was checked before construction.
        unsafe { slice::from_raw_parts(self.entries.as_ptr(), self.count) }
    }
}

impl Drop for SystemModules {
    fn drop(&mut self) {
        // SAFETY: This is the exact base returned by VirtualAlloc and it is
        // released once when the owning value is dropped.
        unsafe {
            core::ptr::write_bytes(self.allocation.as_ptr(), 0, self.allocation_size);
            let _ = virtual_free(self.allocation.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "VirtualAlloc"]
    fn virtual_alloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> *mut c_void;

    #[link_name = "VirtualFree"]
    fn virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32;

    #[link_name = "NtQuerySystemInformation"]
    fn nt_query_system_information(
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[cfg(not(test))]
fn query_modules() -> Result<SystemModules, ModuleError> {
    let mut required = 0_u32;

    // SAFETY: This is the documented size-query form with a null output
    // buffer and a valid return-length pointer.
    let _ = unsafe {
        nt_query_system_information(
            SYSTEM_MODULE_INFORMATION,
            core::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    let required = required as usize;

    if required < size_of::<u32>() + size_of::<ModuleEntry>() || required > MAX_MODULE_BUFFER {
        return Err(ModuleError::InvalidLength);
    }

    // SAFETY: The requested length is bounded and uses ordinary read/write
    // virtual memory. Ownership transfers to `SystemModules` on success.
    let allocation = unsafe {
        virtual_alloc(
            core::ptr::null_mut(),
            required,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    let Some(allocation) = NonNull::new(allocation.cast::<u8>()) else {
        return Err(ModuleError::Allocation);
    };
    let mut returned = 0_u32;

    // SAFETY: `allocation` is writable for `required` bytes and both lengths
    // are representable as u32 because the maximum is 2 MiB.
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_MODULE_INFORMATION,
            allocation.as_ptr().cast(),
            required as u32,
            &mut returned,
        )
    };

    if status < 0 {
        // SAFETY: The allocation has not been transferred and is released once.
        unsafe {
            core::ptr::write_bytes(allocation.as_ptr(), 0, required);
            let _ = virtual_free(allocation.as_ptr().cast(), 0, MEM_RELEASE);
        }

        return Err(ModuleError::Query(status));
    }

    // SAFETY: The returned buffer begins with the module count.
    let count = unsafe { allocation.as_ptr().cast::<u32>().read_unaligned() as usize };
    let entries_offset = align_up(size_of::<u32>(), core::mem::align_of::<ModuleEntry>());
    let entries_bytes = count
        .checked_mul(size_of::<ModuleEntry>())
        .and_then(|bytes| entries_offset.checked_add(bytes));

    if count == 0 || count > MAX_MODULES || entries_bytes.is_none_or(|bytes| bytes > required) {
        // SAFETY: The allocation has not been transferred and is released once.
        unsafe {
            core::ptr::write_bytes(allocation.as_ptr(), 0, required);
            let _ = virtual_free(allocation.as_ptr().cast(), 0, MEM_RELEASE);
        }

        return Err(ModuleError::InvalidCount);
    }

    // SAFETY: The offset and full array extent were checked above.
    let entries = unsafe { NonNull::new_unchecked(allocation.as_ptr().add(entries_offset).cast()) };

    Ok(SystemModules {
        allocation,
        allocation_size: required,
        entries,
        count,
    })
}

#[cfg(test)]
fn query_modules() -> Result<SystemModules, ModuleError> {
    Err(ModuleError::Query(-1))
}

#[cfg(test)]
unsafe fn virtual_free(_address: *mut c_void, _size: usize, _free_type: u32) -> i32 {
    1
}

const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_entry_layout_matches_windows_x64() {
        assert_eq!(size_of::<ModuleEntry>(), 296);
        assert_eq!(align_up(4, core::mem::align_of::<ModuleEntry>()), 8);
    }
}
