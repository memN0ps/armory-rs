//! # Net View BOF
//!
//! Enumerates computers on the network using NetServerEnum.
//!
//! ## MITRE ATT&CK
//! - T1018 - Remote System Discovery
//!
//! ## Arguments
//! - `str`: Domain (empty for default domain). Uses wide string internally.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct ServerInfo101 {
    sv101_platform_id: u32,
    sv101_name: *mut u16,
    sv101_version_major: u32,
    sv101_version_minor: u32,
    sv101_type: u32,
    sv101_comment: *mut u16,
}

unsafe extern "system" {
    fn NetServerEnum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        servertype: u32,
        domain: *const u16,
        resume_handle: *mut u32,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;
const SV_TYPE_ALL: u32 = 0xFFFFFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let domain_str = alloc::string::String::from(parser.get_str());

    unsafe {
        let domain_ptr = if domain_str.is_empty() {
            core::ptr::null()
        } else {
            let wide = to_wide(&domain_str);
            let ptr = wide.as_ptr();
            core::mem::forget(wide);
            ptr
        };

        let display_domain = if domain_str.is_empty() {
            "default domain"
        } else {
            &domain_str
        };

        println!("Computers on {}:\n", display_domain);
        println!("  {:<24} {:<8} {}", "Server Name", "Version", "Comment");
        println!("  {:<24} {:<8} {}", "-----------", "-------", "-------");

        let mut resume_handle: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetServerEnum(
                core::ptr::null(),
                101,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                SV_TYPE_ALL,
                domain_ptr,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetServerEnum failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries =
                    core::slice::from_raw_parts(buf as *const ServerInfo101, entries_read as usize);

                for entry in entries {
                    let name = wide_ptr_to_str(entry.sv101_name);
                    let comment = wide_ptr_to_str(entry.sv101_comment);
                    let version = alloc::format!(
                        "{}.{}",
                        entry.sv101_version_major,
                        entry.sv101_version_minor
                    );

                    println!("  {:<24} {:<8} {}", name, version, comment);
                }
            }

            if !buf.is_null() {
                NetApiBufferFree(buf as *mut _);
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }
    }
}

fn wide_ptr_to_str(ptr: *mut u16) -> alloc::string::String {
    if ptr.is_null() {
        return alloc::string::String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        from_wide(core::slice::from_raw_parts(ptr, len))
    }
}
