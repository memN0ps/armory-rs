//! # Make Token Cert BOF
//!
//! Imports a PFX certificate file and displays certificate information
//! including the subject name, issuer, serial number, and thumbprint (SHA1).
//! This can be used to verify PFX files for certificate-based authentication.
//!
//! ## MITRE ATT&CK
//! - T1649 - Steal or Forge Authentication Certificates
//!
//! ## Arguments
//! - `bin`: PFX file data (raw bytes)
//! - `str`: PFX password

#![no_std]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
const CRYPT_USER_KEYSET: u32 = 0x00001000;
const PKCS12_ALLOW_OVERWRITE_KEY: u32 = 0x00004000;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_ISSUER_FLAG: u32 = 0x1;

const CERT_HASH_PROP_ID: u32 = 3;
#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[repr(C)]
struct CertContext {
    cert_encoding_type: u32,
    pb_cert_encoded: *mut u8,
    cb_cert_encoded: u32,
    cert_info: *mut core::ffi::c_void,
    h_cert_store: *mut core::ffi::c_void,
}
unsafe extern "system" {
    fn PFXImportCertStore(
        pfx: *const CryptDataBlob,
        password: *const u16,
        flags: u32,
    ) -> *mut core::ffi::c_void;

    fn CertEnumCertificatesInStore(
        store: *mut core::ffi::c_void,
        prev_cert: *const CertContext,
    ) -> *const CertContext;

    fn CertGetNameStringA(
        cert_context: *const CertContext,
        name_type: u32,
        flags: u32,
        type_para: *const core::ffi::c_void,
        name_string: *mut u8,
        name_size: u32,
    ) -> u32;

    fn CertGetCertificateContextProperty(
        cert_context: *const CertContext,
        prop_id: u32,
        data: *mut u8,
        data_size: *mut u32,
    ) -> i32;

    fn CertCloseStore(store: *mut core::ffi::c_void, flags: u32) -> i32;
}
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn bytes_to_hex(data: &[u8]) -> String {
    let hex_chars = b"0123456789ABCDEF";
    let mut result = String::with_capacity(data.len() * 3);
    for (i, &b) in data.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        result.push(hex_chars[(b >> 4) as usize] as char);
        result.push(hex_chars[(b & 0x0F) as usize] as char);
    }
    result
}
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pfx_data = alloc::vec::Vec::from(parser.get_bytes());
    let password_str = String::from(parser.get_str());

    if pfx_data.is_empty() {
        eprintln!("Error: PFX data is required.");
        return;
    }

    println!("=== PFX Certificate Import ===\n");
    println!("PFX data size: {} bytes", pfx_data.len());

    unsafe {
        let pfx_blob = CryptDataBlob {
            cb_data: pfx_data.len() as u32,
            pb_data: pfx_data.as_ptr() as *mut u8,
        };

        let password_wide = to_wide(&password_str);

        let store = PFXImportCertStore(
            &pfx_blob,
            password_wide.as_ptr(),
            CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY,
        );

        if store.is_null() {
            eprintln!("PFXImportCertStore failed. Check password and PFX data.");
            return;
        }

        println!("[+] PFX imported successfully.\n");

        let mut cert_ctx: *const CertContext = core::ptr::null();
        let mut cert_index: u32 = 0;

        loop {
            cert_ctx = CertEnumCertificatesInStore(store, cert_ctx);
            if cert_ctx.is_null() {
                break;
            }

            cert_index += 1;
            println!("  [Certificate {}]", cert_index);

            let mut name_buf = vec![0u8; 512];
            let name_len = CertGetNameStringA(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                core::ptr::null(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            );

            if name_len > 1 {
                let name =
                    core::str::from_utf8(&name_buf[..name_len as usize - 1]).unwrap_or("(invalid)");
                println!("    Subject:    {}", name);
            }

            let mut issuer_buf = vec![0u8; 512];
            let issuer_len = CertGetNameStringA(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                core::ptr::null(),
                issuer_buf.as_mut_ptr(),
                issuer_buf.len() as u32,
            );

            if issuer_len > 1 {
                let issuer = core::str::from_utf8(&issuer_buf[..issuer_len as usize - 1])
                    .unwrap_or("(invalid)");
                println!("    Issuer:     {}", issuer);
            }

            let mut hash_size: u32 = 20; // SHA1 = 20 bytes
            let mut hash_buf = vec![0u8; hash_size as usize];
            let ret = CertGetCertificateContextProperty(
                cert_ctx,
                CERT_HASH_PROP_ID,
                hash_buf.as_mut_ptr(),
                &mut hash_size,
            );

            if ret != 0 {
                hash_buf.truncate(hash_size as usize);
                println!("    Thumbprint: {}", bytes_to_hex(&hash_buf));
            }

            let ctx = &*cert_ctx;
            println!("    Cert Size:  {} bytes", ctx.cb_cert_encoded);

            println!();
        }

        if cert_index == 0 {
            println!("  No certificates found in the PFX.");
        } else {
            println!("Total certificates: {}", cert_index);
        }

        CertCloseStore(store, 0);
    }

    println!("\n=== PFX Import Complete ===");
}
