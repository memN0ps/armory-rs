//! # Process List Handles BOF
//!
//! Lists open handles in a target process by calling `NtQuerySystemInformation`
//! with the `SystemHandleInformation` class (16) and filtering results by the
//! specified process ID. For each matching handle, prints the handle value,
//! object type index, and granted access mask.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery
//!
//! ## Arguments
//! - `int`: Target process ID.

#![no_std]

use alloc::vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        buffer: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct SystemHandleTableEntryInfo {
    process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut core::ffi::c_void,
    granted_access: u32,
}

#[repr(C)]
struct SystemHandleInformation {
    number_of_handles: u32,
    handles: [SystemHandleTableEntryInfo; 1],
}
const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;

    println!("Listing handles for PID: {}", pid);
    println!("{}", "=".repeat(60));

    unsafe {
        let mut buf_size: u32 = 1024 * 1024;
        let mut buffer = vec![0u8; buf_size as usize];
        let mut needed: u32 = 0;

        loop {
            let status = NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION,
                buffer.as_mut_ptr(),
                buf_size,
                &mut needed,
            );

            if status == STATUS_INFO_LENGTH_MISMATCH {
                buf_size = if needed > buf_size {
                    needed + 4096
                } else {
                    buf_size * 2
                };
                buffer = vec![0u8; buf_size as usize];
                continue;
            }

            if status < 0 {
                eprintln!(
                    "NtQuerySystemInformation failed with NTSTATUS: 0x{:08X}",
                    status as u32
                );
                return;
            }

            break;
        }

        let info = &*(buffer.as_ptr() as *const SystemHandleInformation);
        let num_handles = info.number_of_handles;

        println!(
            "{:<12} {:<12} {:<12}",
            "Handle", "ObjectType", "AccessMask"
        );
        println!("{}", "-".repeat(40));

        let handles_ptr = info.handles.as_ptr();
        let mut match_count: u32 = 0;

        for i in 0..num_handles {
            let entry = &*handles_ptr.add(i as usize);

            if entry.process_id as u32 == pid {
                println!(
                    "0x{:<10X} {:<12} 0x{:08X}",
                    entry.handle_value, entry.object_type_index, entry.granted_access
                );
                match_count += 1;
            }
        }

        println!("");
        println!("Total handles for PID {}: {}", pid, match_count);
    }
}
