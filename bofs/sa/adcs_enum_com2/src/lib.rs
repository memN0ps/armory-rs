//! # ADCS CA Info Enumeration BOF
//!
//! Enumerates Active Directory Certificate Services (AD CS) CA information
//! and templates by invoking `certutil -TCAInfo` via `CreateProcessA` and
//! capturing the output through an anonymous pipe.
//!
//! ## MITRE ATT&CK
//! - T1649 - Steal or Forge Authentication Certificates
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::format;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessA, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
    WaitForSingleObject,
};

fn run_command(cmd: &str) {
    unsafe {
        let mut sa: SECURITY_ATTRIBUTES = core::mem::zeroed();
        sa.nLength = core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 1;

        let mut h_read: HANDLE = core::ptr::null_mut();
        let mut h_write: HANDLE = core::ptr::null_mut();
        if CreatePipe(&mut h_read, &mut h_write, &sa, 0) == 0 {
            eprintln!("CreatePipe failed ({:#X})", GetLastError());
            return;
        }

        SetHandleInformation(h_read, HANDLE_FLAG_INHERIT, 0);

        let mut si: STARTUPINFOA = core::mem::zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
        si.hStdOutput = h_write;
        si.hStdError = h_write;
        si.dwFlags = STARTF_USESTDHANDLES;

        let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
        let mut cmd_buf = format!("{}\0", cmd);

        let ok = CreateProcessA(
            core::ptr::null(),
            cmd_buf.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1, // bInheritHandles = TRUE
            CREATE_NO_WINDOW,
            core::ptr::null(),
            core::ptr::null(),
            &si,
            &mut pi,
        );

        CloseHandle(h_write); // Must close write end before reading

        if ok != 0 {
            let mut buf = [0u8; 4096];
            loop {
                let mut read: u32 = 0;
                if ReadFile(
                    h_read,
                    buf.as_mut_ptr(),
                    4096,
                    &mut read,
                    core::ptr::null_mut(),
                ) == 0
                    || read == 0
                {
                    break;
                }
                let output = core::str::from_utf8(&buf[..read as usize]).unwrap_or("");
                println!("{}", output);
            }
            WaitForSingleObject(pi.hProcess, 15000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            eprintln!("CreateProcessA failed ({:#X})", GetLastError());
        }

        CloseHandle(h_read);
    }
}

#[rustbof::main]
fn main() {
    println!("=== ADCS CA Info Enumeration via certutil (T1649) ===");
    println!();

    run_command("certutil -TCAInfo");

    println!();
    println!("=== ADCS CA info enumeration complete ===");
}
