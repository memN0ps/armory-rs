//! # SHA1 BOF
//!
//! Computes the SHA1 hash of a file.
//!
//! ## MITRE ATT&CK
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! - `str`: File path to hash.

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::Storage::FileSystem::*;

fn sha1_file(path: &str) {
    unsafe {
        let handle = CreateFileA(
            path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            eprintln!("Error: Could not find file \"{}\"", path);
            return;
        }

        let mut prov: usize = 0;
        if CryptAcquireContextA(
            &mut prov,
            core::ptr::null(),
            core::ptr::null(),
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            CloseHandle(handle);
            eprintln!("Error: Could not initialize HCRYPTPROV context");
            return;
        }

        let mut hash_handle: usize = 0;
        if CryptCreateHash(prov, CALG_SHA1, 0, 0, &mut hash_handle) == 0 {
            CryptReleaseContext(prov, 0);
            CloseHandle(handle);
            eprintln!("Error: CryptCreateHash (SHA1) failed");
            return;
        }

        let mut buf = [0u8; 0x512];
        loop {
            let mut bytes_read: u32 = 0;
            if ReadFile(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
                core::ptr::null_mut(),
            ) == 0
                || bytes_read == 0
            {
                break;
            }
            CryptHashData(hash_handle, buf.as_ptr(), bytes_read, 0);
        }

        let mut sha1 = [0u8; 20];
        let mut hash_len: u32 = 20;
        if CryptGetHashParam(hash_handle, HP_HASHVAL, sha1.as_mut_ptr(), &mut hash_len, 0) != 0 {
            let mut hex = alloc::string::String::with_capacity(40);
            for byte in &sha1[..hash_len as usize] {
                hex.push_str(&alloc::format!("{:02X}", byte));
            }
            println!("SHA1 Hash for {}: {}", path, hex);
        }

        CryptDestroyHash(hash_handle);
        CryptReleaseContext(prov, 0);
        CloseHandle(handle);
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let file_path = parser.get_str();
    sha1_file(file_path);
}
