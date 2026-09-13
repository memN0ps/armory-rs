//! Durable recovery records for reversible kernel state changes.

use crate::bytes::zero;

const MAX_PATH: usize = 260;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_NEW: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const INVALID_HANDLE_VALUE: isize = -1;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut core::ffi::c_void,
    inherit_handle: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LargeInteger {
    quad_part: i64,
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "GetTempPathW"]
    fn get_temp_path_w(length: u32, buffer: *mut u16) -> u32;
    #[link_name = "CreateFileW"]
    fn create_file_w(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: isize,
    ) -> isize;
    #[link_name = "WriteFile"]
    fn write_file(
        file: isize,
        buffer: *const u8,
        bytes: u32,
        written: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    #[link_name = "ReadFile"]
    fn read_file(
        file: isize,
        buffer: *mut u8,
        bytes: u32,
        read: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    #[link_name = "FlushFileBuffers"]
    fn flush_file_buffers(file: isize) -> i32;
    #[link_name = "GetFileSizeEx"]
    fn get_file_size_ex(file: isize, size: *mut LargeInteger) -> i32;
    #[link_name = "CloseHandle"]
    fn close_handle(handle: isize) -> i32;
    #[link_name = "DeleteFileW"]
    fn delete_file_w(name: *const u16) -> i32;
    #[link_name = "LocalFree"]
    fn local_free(memory: isize) -> isize;
    #[link_name = "GetLastError"]
    fn get_last_error() -> u32;
    #[link_name = "ConvertStringSecurityDescriptorToSecurityDescriptorW"]
    fn convert_sddl_w(
        string: *const u16,
        revision: u32,
        descriptor: *mut *mut core::ffi::c_void,
        size: *mut u32,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    Absent,
    Path(u32),
    Security(u32),
    Create(u32),
    Read(u32),
    Write(u32),
    Flush(u32),
    Close(u32),
    Delete(u32),
    InvalidLength,
}

impl RecoveryError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::Absent => "recovery-absent",
            Self::Path(_) => "recovery-path",
            Self::Security(_) => "recovery-acl",
            Self::Create(_) => "recovery-create",
            Self::Read(_) => "recovery-read",
            Self::Write(_) => "recovery-write",
            Self::Flush(_) => "recovery-flush",
            Self::Close(_) => "recovery-close",
            Self::Delete(_) => "recovery-delete",
            Self::InvalidLength => "recovery-length",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::Absent => ERROR_FILE_NOT_FOUND,
            Self::Path(code)
            | Self::Security(code)
            | Self::Create(code)
            | Self::Read(code)
            | Self::Write(code)
            | Self::Flush(code)
            | Self::Close(code)
            | Self::Delete(code) => code,
            Self::InvalidLength => ERROR_INVALID_DATA,
        }
    }
}

pub struct RecoveryStore;

impl RecoveryStore {
    #[cfg(not(test))]
    pub fn write_new(name: &[u16], record: &[u8]) -> Result<(), RecoveryError> {
        if record.is_empty() || record.len() > u32::MAX as usize {
            return Err(RecoveryError::InvalidLength);
        }

        let mut path = [0_u16; MAX_PATH];
        build_path(name, &mut path)?;
        let mut descriptor: *mut core::ffi::c_void = core::ptr::null_mut();
        let sddl = utf16::<30>("D:P(A;;FA;;;SY)(A;;FA;;;BA)");
        let converted =
            unsafe { convert_sddl_w(sddl.as_ptr(), 1, &mut descriptor, core::ptr::null_mut()) };

        if converted == 0 || descriptor.is_null() {
            let code = unsafe { get_last_error() };
            zero_u16(&mut path);
            return Err(RecoveryError::Security(code));
        }

        let attributes = SecurityAttributes {
            length: core::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: descriptor,
            inherit_handle: 0,
        };
        let file = unsafe {
            create_file_w(
                path.as_ptr(),
                GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
                0,
            )
        };

        if file == INVALID_HANDLE_VALUE {
            let code = unsafe { get_last_error() };
            unsafe { local_free(descriptor as isize) };
            zero_u16(&mut path);
            return Err(RecoveryError::Create(code));
        }

        let mut written = 0_u32;
        let write = unsafe {
            write_file(
                file,
                record.as_ptr(),
                record.len() as u32,
                &mut written,
                core::ptr::null_mut(),
            )
        };
        let result = if write == 0 || written as usize != record.len() {
            Err(RecoveryError::Write(unsafe { get_last_error() }))
        } else if unsafe { flush_file_buffers(file) } == 0 {
            Err(RecoveryError::Flush(unsafe { get_last_error() }))
        } else {
            Ok(())
        };
        let close = unsafe { close_handle(file) };
        unsafe { local_free(descriptor as isize) };

        if result.is_err() {
            unsafe { delete_file_w(path.as_ptr()) };
        }

        zero_u16(&mut path);

        if close == 0 && result.is_ok() {
            return Err(RecoveryError::Close(unsafe { get_last_error() }));
        }

        result
    }

    #[cfg(test)]
    pub fn write_new(_name: &[u16], _record: &[u8]) -> Result<(), RecoveryError> {
        Err(RecoveryError::Create(50))
    }

    #[cfg(not(test))]
    pub fn read_exact(name: &[u16], record: &mut [u8]) -> Result<(), RecoveryError> {
        if record.is_empty() || record.len() > u32::MAX as usize {
            return Err(RecoveryError::InvalidLength);
        }

        zero(record);
        let mut path = [0_u16; MAX_PATH];
        build_path(name, &mut path)?;
        let file = unsafe {
            create_file_w(
                path.as_ptr(),
                GENERIC_READ,
                0,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };

        if file == INVALID_HANDLE_VALUE {
            let code = unsafe { get_last_error() };
            zero_u16(&mut path);
            return if matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                Err(RecoveryError::Absent)
            } else {
                Err(RecoveryError::Create(code))
            };
        }

        let mut size = LargeInteger { quad_part: 0 };
        let sized = unsafe { get_file_size_ex(file, &mut size) };
        let mut read = 0_u32;
        let result = if sized == 0 || size.quad_part != record.len() as i64 {
            Err(RecoveryError::InvalidLength)
        } else if unsafe {
            read_file(
                file,
                record.as_mut_ptr(),
                record.len() as u32,
                &mut read,
                core::ptr::null_mut(),
            )
        } == 0
            || read as usize != record.len()
        {
            Err(RecoveryError::Read(unsafe { get_last_error() }))
        } else {
            Ok(())
        };
        let close = unsafe { close_handle(file) };
        zero_u16(&mut path);

        if close == 0 && result.is_ok() {
            zero(record);
            return Err(RecoveryError::Close(unsafe { get_last_error() }));
        }

        if result.is_err() {
            zero(record);
        }

        result
    }

    #[cfg(test)]
    pub fn read_exact(_name: &[u16], record: &mut [u8]) -> Result<(), RecoveryError> {
        zero(record);
        Err(RecoveryError::Absent)
    }

    #[cfg(not(test))]
    pub fn delete(name: &[u16]) -> Result<(), RecoveryError> {
        let mut path = [0_u16; MAX_PATH];
        build_path(name, &mut path)?;
        let deleted = unsafe { delete_file_w(path.as_ptr()) };
        let code = if deleted == 0 {
            unsafe { get_last_error() }
        } else {
            0
        };
        zero_u16(&mut path);

        if deleted == 0 {
            return if matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                Err(RecoveryError::Absent)
            } else {
                Err(RecoveryError::Delete(code))
            };
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn delete(_name: &[u16]) -> Result<(), RecoveryError> {
        Err(RecoveryError::Absent)
    }
}

#[cfg(not(test))]
fn build_path(name: &[u16], output: &mut [u16; MAX_PATH]) -> Result<(), RecoveryError> {
    if name.is_empty() || name.last() != Some(&0) {
        return Err(RecoveryError::Path(ERROR_INVALID_DATA));
    }

    let temp_length = unsafe { get_temp_path_w(output.len() as u32, output.as_mut_ptr()) };

    if temp_length == 0 || temp_length as usize >= output.len() {
        return Err(RecoveryError::Path(if temp_length == 0 {
            unsafe { get_last_error() }
        } else {
            ERROR_INSUFFICIENT_BUFFER
        }));
    }

    let required = temp_length as usize + name.len();

    if required > output.len() {
        return Err(RecoveryError::Path(ERROR_INSUFFICIENT_BUFFER));
    }

    output[temp_length as usize..required].copy_from_slice(name);

    Ok(())
}

const fn utf16<const N: usize>(value: &str) -> [u16; N] {
    let bytes = value.as_bytes();
    let mut output = [0_u16; N];
    let mut index = 0;

    while index < bytes.len() && index + 1 < N {
        output[index] = bytes[index] as u16;
        index += 1;
    }

    output
}

fn zero_u16(value: &mut [u16]) {
    for item in value {
        unsafe { core::ptr::write_volatile(item, 0) };
    }
}

pub fn checksum(bytes: &[u8]) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325_u64;

    for byte in bytes {
        value ^= *byte as u64;
        value = value.wrapping_mul(0x1000_0000_01b3);
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_changes_with_record() {
        assert_ne!(checksum(b"record-a"), checksum(b"record-b"));
    }

    #[test]
    fn test_store_fails_closed() {
        let mut record = [0xaa; 8];

        assert_eq!(
            RecoveryStore::read_exact(&[0], &mut record),
            Err(RecoveryError::Absent)
        );
        assert_eq!(record, [0; 8]);
        assert!(RecoveryStore::write_new(&[0], &record).is_err());
        assert_eq!(RecoveryStore::delete(&[0]), Err(RecoveryError::Absent));
    }
}
