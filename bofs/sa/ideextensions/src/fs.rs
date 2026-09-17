//! Local filesystem helpers for this BOF.

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FindClose, FindFirstFileW,
        FindNextFileW, GetFileAttributesExW, GetFileExInfoStandard, WIN32_FILE_ATTRIBUTE_DATA,
        WIN32_FIND_DATAW,
    },
    System::Environment::GetEnvironmentVariableW,
};

const MAX_PATH_UNITS: usize = 32760;

#[derive(Clone)]
pub struct Metadata {
    pub is_directory: bool,
    pub is_reparse_point: bool,
}

#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub metadata: Metadata,
}

pub fn environment(name: &str) -> Result<String, u32> {
    let name = wide_null(name);
    let required = unsafe { GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
    if required == 0 || required as usize > MAX_PATH_UNITS {
        return Err(unsafe { GetLastError() });
    }

    let mut value = vec![0u16; required as usize];
    let written = unsafe { GetEnvironmentVariableW(name.as_ptr(), value.as_mut_ptr(), required) };
    if written == 0 || written >= required {
        return Err(unsafe { GetLastError() });
    }

    Ok(String::from_utf16_lossy(&value[..written as usize]))
}

pub fn join(base: &str, child: &str) -> String {
    let child = child.trim_start_matches(['\\', '/']);
    let mut value = String::with_capacity(base.len() + child.len() + 1);
    value.push_str(base);
    if base.ends_with(['\\', '/']) {
        value.push_str(child);
    } else {
        value.push('\\');
        value.push_str(child);
    }

    value
}

pub fn metadata(path: &str) -> Result<Metadata, u32> {
    let path = wide_null(path);
    let mut data: WIN32_FILE_ATTRIBUTE_DATA = unsafe { core::mem::zeroed() };
    if unsafe {
        GetFileAttributesExW(
            path.as_ptr(),
            GetFileExInfoStandard,
            &mut data as *mut _ as *mut core::ffi::c_void,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }

    Ok(metadata_from_parts(
        data.dwFileAttributes,
        data.nFileSizeHigh,
        data.nFileSizeLow,
    ))
}

pub fn children(path: &str, maximum: usize) -> Result<Vec<Entry>, u32> {
    let query = wide_null(&join(path, "*"));
    let mut data: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
    let handle = unsafe { FindFirstFileW(query.as_ptr(), &mut data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }

    let mut entries = Vec::new();
    let mut final_error = 0u32;
    loop {
        let name = wide_to_string(&data.cFileName);
        if name != "." && name != ".." && entries.len() < maximum {
            entries.push(Entry {
                path: join(path, &name),
                name,
                metadata: metadata_from_parts(
                    data.dwFileAttributes,
                    data.nFileSizeHigh,
                    data.nFileSizeLow,
                ),
            });
        }
        if entries.len() >= maximum {
            break;
        }
        if unsafe { FindNextFileW(handle, &mut data) } == 0 {
            let status = unsafe { GetLastError() };
            if status != ERROR_NO_MORE_FILES {
                final_error = status;
            }
            break;
        }
    }
    unsafe { FindClose(handle) };

    if final_error == 0 {
        Ok(entries)
    } else {
        Err(final_error)
    }
}

fn metadata_from_parts(attributes: u32, high: u32, low: u32) -> Metadata {
    let _ = (high, low);
    Metadata {
        is_directory: attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        is_reparse_point: attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(value.len());

    String::from_utf16_lossy(&value[..length])
}
