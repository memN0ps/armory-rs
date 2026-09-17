//! # System Tray Discovery BOF
//!
//! Reports the taskbar host and bounded Windows 11 notification-area metadata.
//! It does not use undocumented Explorer toolbar structures or read another
//! process's memory.
//!
//! ## MITRE ATT&CK
//! - T1012 - Query Registry
//! - T1057 - Process Discovery
//!
//! ## Arguments
//! Optional packed string: `verbose` to include full executable paths.

#![no_std]

use alloc::{string::String, vec, vec::Vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

type Handle = *mut c_void;
type HKey = *mut c_void;
type HWnd = *mut c_void;

unsafe extern "system" {
    fn FindWindowW(class_name: *const u16, window_name: *const u16) -> HWnd;
    fn GetWindowThreadProcessId(window: HWnd, process_id: *mut u32) -> u32;
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn RegOpenKeyExW(
        key: HKey,
        subkey: *const u16,
        options: u32,
        access: u32,
        result: *mut HKey,
    ) -> i32;
    fn RegEnumKeyExW(
        key: HKey,
        index: u32,
        name: *mut u16,
        name_size: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_size: *mut u32,
        last_write: *mut c_void,
    ) -> i32;
    fn RegQueryValueExW(
        key: HKey,
        name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: HKey) -> i32;
}

const HKEY_CURRENT_USER: HKey = 0x8000_0001usize as HKey;
const KEY_READ: u32 = 0x0002_0019;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const ERROR_SUCCESS: i32 = 0;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const MAX_ITEMS: u32 = 128;
const MAX_PATH_UNITS: usize = 32768;
const NOTIFY_SETTINGS: &str = "Control Panel\\NotifyIconSettings";

fn wide_z(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn parse_verbose(args: *mut u8, len: usize) -> Result<bool, ()> {
    if args.is_null() || len == 0 {
        return Ok(false);
    }

    let buffer = unsafe { core::slice::from_raw_parts(args, len) };
    if buffer.len() < 9 {
        return Err(());
    }

    let declared = u32::from_le_bytes(buffer[..4].try_into().map_err(|_| ())?) as usize;
    let length = u32::from_le_bytes(buffer[4..8].try_into().map_err(|_| ())?) as usize;
    if declared != buffer.len() - 4 || length <= 1 || 8 + length != buffer.len() {
        return Err(());
    }

    let value = buffer.get(8..8 + length).ok_or(())?;
    if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
        return Err(());
    }

    let value = core::str::from_utf8(&value[..length - 1]).map_err(|_| ())?;
    if value.eq_ignore_ascii_case("verbose") || value.eq_ignore_ascii_case("/verbose") {
        Ok(true)
    } else {
        Err(())
    }
}

fn query_string(key: HKey, name: &str) -> Option<String> {
    let name = wide_z(name);
    let mut value_type = 0u32;
    let mut size = 0u32;
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            core::ptr::null_mut(),
            &mut size,
        )
    } != ERROR_SUCCESS
        || (value_type != REG_SZ && value_type != REG_EXPAND_SZ)
        || size == 0
        || size > 64 * 1024
        || size % 2 != 0
    {
        return None;
    }

    let mut buffer = vec![0u16; size as usize / 2];
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut size,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }

    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn query_dword(key: HKey, name: &str) -> Option<u32> {
    let name = wide_z(name);
    let mut value_type = 0u32;
    let mut value = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            &mut value as *mut u32 as *mut u8,
            &mut size,
        )
    };

    (status == ERROR_SUCCESS && value_type == REG_DWORD && size == 4).then_some(value)
}

fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn taskbar_host(verbose: bool) {
    let class_name = wide_z("Shell_TrayWnd");
    let window = unsafe { FindWindowW(class_name.as_ptr(), core::ptr::null()) };
    if window.is_null() {
        println!("Taskbar host: <not present in this desktop session>");
        return;
    }

    let mut process_id = 0u32;
    unsafe { GetWindowThreadProcessId(window, &mut process_id) };
    if process_id == 0 {
        println!("Taskbar host: <process unavailable>");
        return;
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        println!("Taskbar host: pid={} | path unavailable", process_id);
        return;
    }

    let mut path = vec![0u16; MAX_PATH_UNITS];
    let mut size = path.len() as u32;
    let success = unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(process) };
    if success == 0 || size == 0 || size as usize > path.len() {
        println!("Taskbar host: pid={} | path unavailable", process_id);
        return;
    }

    let path = String::from_utf16_lossy(&path[..size as usize]);
    if verbose {
        println!("Taskbar host: {} | pid={}", path, process_id);
    } else {
        println!("Taskbar host: {} | pid={}", base_name(&path), process_id);
    }
}

fn notification_items(verbose: bool) -> Result<(u32, bool), u32> {
    let path = wide_z(NOTIFY_SETTINGS);
    let mut root = core::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut root) };
    if status != ERROR_SUCCESS {
        return Err(status as u32);
    }

    let mut shown = 0u32;
    let mut index = 0u32;
    let mut truncated = false;
    loop {
        let mut name = [0u16; 256];
        let mut name_size = (name.len() - 1) as u32;
        let status = unsafe {
            RegEnumKeyExW(
                root,
                index,
                name.as_mut_ptr(),
                &mut name_size,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            unsafe { RegCloseKey(root) };
            return Err(status as u32);
        }
        index += 1;
        if shown >= MAX_ITEMS {
            truncated = true;
            break;
        }

        let key_name = String::from_utf16_lossy(&name[..name_size as usize]);
        let key_name_wide = wide_z(&key_name);
        let mut item = core::ptr::null_mut();
        if unsafe { RegOpenKeyExW(root, key_name_wide.as_ptr(), 0, KEY_READ, &mut item) }
            != ERROR_SUCCESS
        {
            continue;
        }

        let executable = query_string(item, "ExecutablePath").unwrap_or_default();
        let tooltip = query_string(item, "InitialTooltip").unwrap_or_default();
        let promoted = query_dword(item, "IsPromoted");
        unsafe { RegCloseKey(item) };
        if executable.is_empty() && tooltip.is_empty() {
            continue;
        }

        shown += 1;
        let display = if tooltip.is_empty() {
            "<no tooltip>"
        } else {
            tooltip.as_str()
        };
        let image = if executable.is_empty() {
            "<path unavailable>"
        } else if verbose {
            executable.as_str()
        } else {
            base_name(&executable)
        };
        println!(
            "[{}] {} | {} | promoted={}",
            shown,
            display,
            image,
            match promoted {
                Some(0) => "no",
                Some(_) => "yes",
                None => "unknown",
            }
        );
    }

    unsafe { RegCloseKey(root) };
    Ok((shown, truncated))
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    match parse_verbose(args, len) {
        Err(()) => eprintln!("Usage: trayscout [verbose]"),
        Ok(verbose) => {
            println!("System tray discovery | verbose={}", verbose);
            taskbar_host(verbose);
            match notification_items(verbose) {
                Ok((shown, truncated)) => println!(
                    "Notification records: {}{}",
                    shown,
                    if truncated {
                        " | output limit reached"
                    } else {
                        ""
                    }
                ),
                Err(error) => println!("Notification metadata unavailable: 0x{:X}", error),
            }
        }
    }
}
