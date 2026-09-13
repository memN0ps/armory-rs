//! Read-only loading of exact Windows system images for PE profile checks.

use crate::{heap::HeapBuffer, kernel::ImageIdentity, kernel::parse_image_identity};
use core::ffi::c_void;

const MAX_PATH: usize = 260;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: isize = -1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemImageError {
    InvalidName,
    SystemDirectory(u32),
    Open(u32),
    Size(u32),
    InvalidSize,
    Allocation,
    Read(u32),
    Close(u32),
    InvalidImage,
}

impl SystemImageError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::InvalidName => "system-image-name",
            Self::SystemDirectory(_) => "system-image-directory",
            Self::Open(_) => "system-image-open",
            Self::Size(_) => "system-image-size",
            Self::InvalidSize => "system-image-length",
            Self::Allocation => "system-image-allocation",
            Self::Read(_) => "system-image-read",
            Self::Close(_) => "system-image-close",
            Self::InvalidImage => "system-image-pe",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::SystemDirectory(code)
            | Self::Open(code)
            | Self::Size(code)
            | Self::Read(code)
            | Self::Close(code) => code,
            Self::Allocation => 8,
            Self::InvalidName | Self::InvalidSize | Self::InvalidImage => 13,
        }
    }
}

pub struct SystemImage {
    bytes: HeapBuffer,
    length: usize,
    identity: ImageIdentity,
}

impl SystemImage {
    #[cfg(not(test))]
    pub fn open(name: &[u8]) -> Result<Self, SystemImageError> {
        if !valid_name(name) {
            return Err(SystemImageError::InvalidName);
        }

        let mut path = [0_u8; MAX_PATH];

        // SAFETY: path is a writable MAX_PATH ANSI buffer. Accepted system
        // image names are restricted to ASCII basenames.
        let directory_length =
            unsafe { get_system_directory_a(path.as_mut_ptr(), MAX_PATH as u32) };

        if directory_length == 0 {
            return Err(SystemImageError::SystemDirectory(last_error()));
        }

        let mut offset = directory_length as usize;

        if offset >= MAX_PATH - name.len() - 2 {
            return Err(SystemImageError::InvalidName);
        }

        path[offset] = b'\\';
        offset += 1;

        for byte in name {
            path[offset] = *byte;
            offset += 1;
        }

        path[offset] = 0;

        // SAFETY: path is terminated, and all other arguments follow the
        // documented read-only CreateFileA contract.
        let handle = unsafe {
            create_file_a(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(SystemImageError::Open(last_error()));
        }

        let mut file = FileHandle {
            value: handle,
            close_error: 0,
        };
        let mut high_size = 0_u32;

        // SAFETY: high_size is writable and file is a live read handle.
        let low_size = unsafe { get_file_size(file.value, &mut high_size) };

        if low_size == u32::MAX {
            return Err(SystemImageError::Size(last_error()));
        }

        if high_size != 0 {
            return Err(SystemImageError::InvalidSize);
        }

        let length = low_size as usize;

        if !(0x1000..=MAX_IMAGE_BYTES).contains(&length) {
            return Err(SystemImageError::InvalidSize);
        }

        let mut bytes = HeapBuffer::new(length).ok_or(SystemImageError::Allocation)?;
        let mut total = 0_usize;

        while total < length {
            let chunk = core::cmp::min(length - total, u32::MAX as usize) as u32;
            let mut read = 0_u32;

            // SAFETY: The output slice has room for chunk bytes and the file
            // handle remains live for the complete call.
            if unsafe {
                read_file(
                    file.value,
                    bytes.as_mut_slice()[total..].as_mut_ptr(),
                    chunk,
                    &mut read,
                    core::ptr::null_mut(),
                )
            } == 0
            {
                return Err(SystemImageError::Read(last_error()));
            }

            if read == 0 {
                return Err(SystemImageError::Read(38));
            }

            total += read as usize;
        }

        file.close()?;
        let identity =
            parse_image_identity(bytes.as_slice()).ok_or(SystemImageError::InvalidImage)?;

        Ok(Self {
            bytes,
            length,
            identity,
        })
    }

    #[cfg(test)]
    pub fn open(_name: &[u8]) -> Result<Self, SystemImageError> {
        Err(SystemImageError::Open(50))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }

    pub const fn identity(&self) -> ImageIdentity {
        self.identity
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
        && name.ends_with(b".dll")
}

#[cfg(not(test))]
struct FileHandle {
    value: isize,
    close_error: u32,
}

#[cfg(not(test))]
impl FileHandle {
    fn close(&mut self) -> Result<(), SystemImageError> {
        if self.value == INVALID_HANDLE_VALUE {
            return Ok(());
        }

        // SAFETY: value is a live file handle owned by this guard.
        if unsafe { close_handle(self.value) } == 0 {
            self.close_error = last_error();
            return Err(SystemImageError::Close(self.close_error));
        }

        self.value = INVALID_HANDLE_VALUE;

        Ok(())
    }
}

#[cfg(not(test))]
impl Drop for FileHandle {
    fn drop(&mut self) {
        if self.value == INVALID_HANDLE_VALUE {
            return;
        }

        // SAFETY: value is either a live owned handle or already invalid.
        if unsafe { close_handle(self.value) } == 0 {
            self.close_error = last_error();
        }

        self.value = INVALID_HANDLE_VALUE;
    }
}

#[cfg(not(test))]
fn last_error() -> u32 {
    // SAFETY: GetLastError takes no arguments and is thread-local.
    unsafe { get_last_error() }
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "GetSystemDirectoryA"]
    fn get_system_directory_a(buffer: *mut u8, size: u32) -> u32;

    #[link_name = "CreateFileA"]
    fn create_file_a(
        name: *const u8,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        attributes: u32,
        template: isize,
    ) -> isize;

    #[link_name = "GetFileSize"]
    fn get_file_size(file: isize, high: *mut u32) -> u32;

    #[link_name = "ReadFile"]
    fn read_file(
        file: isize,
        output: *mut u8,
        length: u32,
        read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;

    #[link_name = "CloseHandle"]
    fn close_handle(handle: isize) -> i32;

    #[link_name = "GetLastError"]
    fn get_last_error() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_simple_dll_basenames() {
        assert!(valid_name(b"wdigest.dll"));
        assert!(valid_name(b"component-name_2.dll"));
        assert!(!valid_name(b"wdigest.sys"));
        assert!(!valid_name(b"..\\wdigest.dll"));
        assert!(!valid_name(b"C:\\Windows\\wdigest.dll"));
    }
}
