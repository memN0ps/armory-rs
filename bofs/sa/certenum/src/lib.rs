//! # Personal Certificate Enumeration BOF
//!
//! Enumerates Current User and Local Machine personal certificate stores,
//! including subject, issuer, expiry, enhanced-key usages, SHA-1 thumbprint,
//! and private-key presence.
//!
//! ## MITRE ATT&CK
//! - T1649 - Steal or Forge Authentication Certificates
//! - T1552.004 - Unsecured Credentials: Private Keys
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use core::fmt::Write;
use rustbof::{eprintln, println};

type CertStore = *mut core::ffi::c_void;

#[repr(C)]
struct CryptDataBlob {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
struct CryptAlgorithmIdentifier {
    object_id: *mut u8,
    parameters: CryptDataBlob,
}

#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
struct CertInfoPrefix {
    version: u32,
    serial_number: CryptDataBlob,
    signature_algorithm: CryptAlgorithmIdentifier,
    issuer: CryptDataBlob,
    not_before: FileTime,
    not_after: FileTime,
}

#[repr(C)]
struct CertContext {
    encoding_type: u32,
    encoded: *const u8,
    encoded_size: u32,
    cert_info: *const CertInfoPrefix,
    store: CertStore,
}

#[repr(C)]
struct EnhancedKeyUsage {
    count: u32,
    object_ids: *mut *mut u8,
}

#[repr(C)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

unsafe extern "system" {
    fn CertOpenStore(
        provider: *const u8,
        encoding_type: u32,
        crypt_provider: usize,
        flags: u32,
        parameter: *const core::ffi::c_void,
    ) -> CertStore;
    fn CertCloseStore(store: CertStore, flags: u32) -> i32;
    fn CertFreeCertificateContext(context: *const CertContext) -> i32;
    fn CertEnumCertificatesInStore(
        store: CertStore,
        previous: *const CertContext,
    ) -> *const CertContext;
    fn CertGetNameStringW(
        context: *const CertContext,
        name_type: u32,
        flags: u32,
        type_parameter: *const core::ffi::c_void,
        name: *mut u16,
        name_size: u32,
    ) -> u32;
    fn CertGetCertificateContextProperty(
        context: *const CertContext,
        property_id: u32,
        data: *mut core::ffi::c_void,
        data_size: *mut u32,
    ) -> i32;
    fn CertGetEnhancedKeyUsage(
        context: *const CertContext,
        flags: u32,
        usage: *mut EnhancedKeyUsage,
        usage_size: *mut u32,
    ) -> i32;
    fn CryptAcquireCertificatePrivateKey(
        context: *const CertContext,
        flags: u32,
        reserved: *mut core::ffi::c_void,
        key: *mut usize,
        key_spec: *mut u32,
        caller_free: *mut i32,
    ) -> i32;
    fn CryptGetUserKey(provider: usize, key_spec: u32, key: *mut usize) -> i32;
    fn CryptGetKeyParam(
        key: usize,
        parameter: u32,
        data: *mut u8,
        size: *mut u32,
        flags: u32,
    ) -> i32;
    fn CryptDestroyKey(key: usize) -> i32;
    fn CryptReleaseContext(provider: usize, flags: u32) -> i32;
    fn NCryptGetProperty(
        key: usize,
        property: *const u16,
        output: *mut u8,
        output_size: u32,
        result_size: *mut u32,
        flags: u32,
    ) -> i32;
    fn NCryptFreeObject(object: usize) -> i32;
    fn FileTimeToSystemTime(file_time: *const FileTime, system_time: *mut SystemTime) -> i32;
}

const CERT_STORE_PROV_SYSTEM_W: usize = 10;
const CERT_STORE_OPEN_EXISTING_FLAG: u32 = 0x00004000;
const CERT_STORE_READONLY_FLAG: u32 = 0x00008000;
const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 0x00010000;
const CERT_SYSTEM_STORE_LOCAL_MACHINE: u32 = 0x00020000;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_ISSUER_FLAG: u32 = 1;
const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;
const CERT_HASH_PROP_ID: u32 = 3;
const CRYPT_ACQUIRE_SILENT_FLAG: u32 = 0x00000040;
const CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG: u32 = 0x00010000;
const CERT_NCRYPT_KEY_SPEC: u32 = u32::MAX;
const KP_PERMISSIONS: u32 = 6;
const CRYPT_EXPORT: u32 = 4;
const NCRYPT_ALLOW_EXPORT_MASK: u32 = 0x0000000F;

fn name_string(context: *const CertContext, flags: u32) -> String {
    unsafe {
        let needed = CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            core::ptr::null(),
            core::ptr::null_mut(),
            0,
        );
        if needed <= 1 {
            return String::from("<not available>");
        }

        let mut buffer = vec![0u16; needed as usize];
        if CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            core::ptr::null(),
            buffer.as_mut_ptr(),
            needed,
        ) == 0
        {
            return String::from("<not available>");
        }

        String::from_utf16_lossy(&buffer[..needed.saturating_sub(1) as usize])
    }
}

fn thumbprint(context: *const CertContext) -> String {
    unsafe {
        let mut size = 0u32;
        if CertGetCertificateContextProperty(
            context,
            CERT_HASH_PROP_ID,
            core::ptr::null_mut(),
            &mut size,
        ) == 0
            || size == 0
        {
            return String::from("<not available>");
        }

        let mut bytes = vec![0u8; size as usize];
        if CertGetCertificateContextProperty(
            context,
            CERT_HASH_PROP_ID,
            bytes.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
        ) == 0
        {
            return String::from("<not available>");
        }

        let mut value = String::with_capacity(size as usize * 2);
        for byte in bytes.iter().take(size as usize) {
            let _ = write!(&mut value, "{:02X}", byte);
        }
        value
    }
}

fn expiry(context: *const CertContext) -> String {
    unsafe {
        if context.is_null() || (*context).cert_info.is_null() {
            return String::from("<not available>");
        }

        let mut value: SystemTime = core::mem::zeroed();
        if FileTimeToSystemTime(&(*(*context).cert_info).not_after, &mut value) == 0 {
            return String::from("<not available>");
        }

        let mut output = String::new();
        let _ = write!(
            &mut output,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            value.year, value.month, value.day, value.hour, value.minute, value.second
        );
        output
    }
}

fn oid_string(pointer: *const u8) -> Option<String> {
    if pointer.is_null() {
        return None;
    }

    unsafe {
        let mut length = 0usize;
        while length < 128 && *pointer.add(length) != 0 {
            length += 1;
        }
        if length == 0 || length == 128 {
            return None;
        }
        core::str::from_utf8(core::slice::from_raw_parts(pointer, length))
            .ok()
            .map(String::from)
    }
}

fn enhanced_key_usage(context: *const CertContext) -> String {
    unsafe {
        let mut size = 0u32;
        if CertGetEnhancedKeyUsage(context, 0, core::ptr::null_mut(), &mut size) == 0
            || size < core::mem::size_of::<EnhancedKeyUsage>() as u32
            || size > 64 * 1024
        {
            return String::from("<not available>");
        }

        let mut buffer = vec![0u8; size as usize];
        let usage = buffer.as_mut_ptr() as *mut EnhancedKeyUsage;
        if CertGetEnhancedKeyUsage(context, 0, usage, &mut size) == 0 {
            return String::from("<not available>");
        }
        if (*usage).count == 0 {
            return String::from("<any purpose>");
        }
        if (*usage).count > 32 || (*usage).object_ids.is_null() {
            return String::from("<invalid or excessive usage list>");
        }

        let mut value = String::new();
        for index in 0..(*usage).count as usize {
            if let Some(oid) = oid_string(*(*usage).object_ids.add(index)) {
                if !value.is_empty() {
                    value.push_str(", ");
                }
                value.push_str(&oid);
            }
        }
        if value.is_empty() {
            String::from("<not available>")
        } else {
            value
        }
    }
}

fn has_private_key_property(context: *const CertContext) -> bool {
    unsafe {
        let mut size = 0u32;
        CertGetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            core::ptr::null_mut(),
            &mut size,
        ) != 0
    }
}

fn private_key_state(context: *const CertContext) -> &'static str {
    if !has_private_key_property(context) {
        return "absent";
    }

    unsafe {
        let mut provider_or_key = 0usize;
        let mut key_spec = 0u32;
        let mut caller_free = 0i32;
        if CryptAcquireCertificatePrivateKey(
            context,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
            core::ptr::null_mut(),
            &mut provider_or_key,
            &mut key_spec,
            &mut caller_free,
        ) == 0
        {
            return "present; exportability unavailable";
        }

        let exportable = if key_spec == CERT_NCRYPT_KEY_SPEC {
            let property: [u16; 14] = [
                'E' as u16, 'x' as u16, 'p' as u16, 'o' as u16, 'r' as u16, 't' as u16, ' ' as u16,
                'P' as u16, 'o' as u16, 'l' as u16, 'i' as u16, 'c' as u16, 'y' as u16, 0,
            ];
            let mut policy = 0u32;
            let mut size = 0u32;
            let status = NCryptGetProperty(
                provider_or_key,
                property.as_ptr(),
                &mut policy as *mut _ as *mut u8,
                core::mem::size_of::<u32>() as u32,
                &mut size,
                0,
            );
            (status == 0 && size == core::mem::size_of::<u32>() as u32)
                .then_some(policy & NCRYPT_ALLOW_EXPORT_MASK != 0)
        } else {
            let mut key = 0usize;
            if CryptGetUserKey(provider_or_key, key_spec, &mut key) == 0 {
                None
            } else {
                let mut permissions = 0u32;
                let mut size = core::mem::size_of::<u32>() as u32;
                let result = CryptGetKeyParam(
                    key,
                    KP_PERMISSIONS,
                    &mut permissions as *mut _ as *mut u8,
                    &mut size,
                    0,
                );
                CryptDestroyKey(key);
                (result != 0 && size == core::mem::size_of::<u32>() as u32)
                    .then_some(permissions & CRYPT_EXPORT != 0)
            }
        };

        if caller_free != 0 {
            if key_spec == CERT_NCRYPT_KEY_SPEC {
                NCryptFreeObject(provider_or_key);
            } else {
                CryptReleaseContext(provider_or_key, 0);
            }
        }

        match exportable {
            Some(true) => "present; exportable",
            Some(false) => "present; not exportable",
            None => "present; exportability unavailable",
        }
    }
}

fn enumerate_store(label: &str, location: u32) {
    const MAX_CERTIFICATES: u32 = 64;

    let store_name = ['M' as u16, 'Y' as u16, 0];

    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W as *const u8,
            0,
            0,
            location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
            store_name.as_ptr() as *const core::ffi::c_void,
        );
        if store.is_null() {
            eprintln!("{} personal store: open failed", label);
            return;
        }

        println!("{} personal store:", label);
        let mut previous: *const CertContext = core::ptr::null();
        let mut count = 0u32;
        let mut truncated = false;
        loop {
            if count >= MAX_CERTIFICATES {
                truncated = true;
                if !previous.is_null() {
                    CertFreeCertificateContext(previous);
                }
                break;
            }

            let context = CertEnumCertificatesInStore(store, previous);
            if context.is_null() {
                break;
            }
            previous = context;
            count += 1;

            println!("  [{}] {}", count, name_string(context, 0));
            println!(
                "      issuer:      {}",
                name_string(context, CERT_NAME_ISSUER_FLAG)
            );
            println!("      expires:     {}", expiry(context));
            println!("      EKU:         {}", enhanced_key_usage(context));
            println!("      thumbprint:  {}", thumbprint(context));
            println!("      private key: {}", private_key_state(context));
        }

        if count == 0 {
            println!("  <empty>");
        }
        println!(
            "  certificates shown: {}{}\n",
            count,
            if truncated {
                " | row limit reached"
            } else {
                ""
            }
        );
        CertCloseStore(store, 0);
    }
}

#[rustbof::main]
fn main() {
    println!("Personal certificate inventory\n");
    enumerate_store("Current User", CERT_SYSTEM_STORE_CURRENT_USER);
    enumerate_store("Local Machine", CERT_SYSTEM_STORE_LOCAL_MACHINE);
}
