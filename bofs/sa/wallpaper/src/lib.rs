//! # Desktop Wallpaper Inventory BOF
//!
//! Enumerates the current wallpaper path for each desktop monitor through the
//! documented IDesktopWallpaper COM interface. It does not read image files.
//!
//! ## MITRE ATT&CK
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

type HResult = i32;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency: u32) -> HResult;
    fn CoCreateInstance(
        class_id: *const Guid,
        outer: *mut c_void,
        context: u32,
        interface_id: *const Guid,
        object: *mut *mut c_void,
    ) -> HResult;
    fn CoTaskMemFree(memory: *mut c_void);
    fn CoUninitialize();
    fn RegGetValueW(
        key: *mut c_void,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        value_type: *mut u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> i32;
}

const S_OK: HResult = 0;
const S_FALSE: HResult = 1;
const RPC_E_CHANGED_MODE: HResult = 0x80010106u32 as i32;
const COINIT_APARTMENTTHREADED: u32 = 2;
const CLSCTX_ALL: u32 = 23;
const MAX_MONITORS: u32 = 32;
const MAX_STRING_UNITS: usize = 32768;
const HKEY_CURRENT_USER: *mut c_void = 0x80000001usize as *mut c_void;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const MAX_REGISTRY_BYTES: u32 = 64 * 1024;

const CLSID_DESKTOP_WALLPAPER: Guid = Guid {
    data1: 0xC2CF3110,
    data2: 0x460E,
    data3: 0x4FC1,
    data4: [0xB9, 0xD0, 0x8A, 0x1C, 0x0C, 0x9C, 0xC4, 0xBD],
};

const IID_IDESKTOP_WALLPAPER: Guid = Guid {
    data1: 0xB92B56A9,
    data2: 0x8B55,
    data3: 0x4E14,
    data4: [0x9A, 0x89, 0x01, 0x99, 0xBB, 0xB6, 0xF9, 0x3B],
};

unsafe fn vtable_entry(object: *mut c_void, index: usize) -> *const c_void {
    unsafe { *(*(object as *mut *mut *mut c_void)).add(index) as *const c_void }
}

unsafe fn release(object: *mut c_void) {
    if !object.is_null() {
        type Release = unsafe extern "system" fn(*mut c_void) -> u32;
        let function: Release = unsafe { core::mem::transmute(vtable_entry(object, 2)) };
        unsafe { function(object) };
    }
}

fn wide_pointer(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::from("<not configured>");
    }
    unsafe {
        let mut length = 0usize;
        while length < MAX_STRING_UNITS && *pointer.add(length) != 0 {
            length += 1;
        }
        if length == MAX_STRING_UNITS {
            String::from("<path exceeds limit>")
        } else {
            String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length))
        }
    }
}

fn wide_z(value: &str) -> alloc::vec::Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn registry_wallpaper() -> Result<String, u32> {
    let subkey = wide_z("Control Panel\\Desktop");
    let value = wide_z("WallPaper");
    let mut value_type = 0u32;
    let mut size = 0u32;
    let first = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            &mut value_type,
            core::ptr::null_mut(),
            &mut size,
        )
    };

    if first != 0 || size == 0 || size > MAX_REGISTRY_BYTES || size % 2 != 0 {
        return Err(if first != 0 { first as u32 } else { 13 });
    }

    let mut buffer = vec![0u16; size as usize / 2];
    let second = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            &mut value_type,
            buffer.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };

    if second != 0 {
        return Err(second as u32);
    }

    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn enumerate_wallpapers() -> Result<(u32, bool), (&'static str, HResult)> {
    unsafe {
        let initialize = CoInitializeEx(core::ptr::null_mut(), COINIT_APARTMENTTHREADED);
        let uninitialize = initialize == S_OK || initialize == S_FALSE;
        if initialize < 0 && initialize != RPC_E_CHANGED_MODE {
            return Err(("CoInitializeEx", initialize));
        }

        let mut wallpaper = core::ptr::null_mut();
        let create = CoCreateInstance(
            &CLSID_DESKTOP_WALLPAPER,
            core::ptr::null_mut(),
            CLSCTX_ALL,
            &IID_IDESKTOP_WALLPAPER,
            &mut wallpaper,
        );
        if create < 0 || wallpaper.is_null() {
            if uninitialize {
                CoUninitialize();
            }
            return Err(("CoCreateInstance(IDesktopWallpaper)", create));
        }

        type GetCount = unsafe extern "system" fn(*mut c_void, *mut u32) -> HResult;
        type GetMonitorPath = unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16) -> HResult;
        type GetWallpaper =
            unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut u16) -> HResult;
        let get_count: GetCount = core::mem::transmute(vtable_entry(wallpaper, 6));
        let get_monitor_path: GetMonitorPath = core::mem::transmute(vtable_entry(wallpaper, 5));
        let get_wallpaper: GetWallpaper = core::mem::transmute(vtable_entry(wallpaper, 4));

        let mut count = 0u32;
        let status = get_count(wallpaper, &mut count);
        if status < 0 {
            release(wallpaper);
            if uninitialize {
                CoUninitialize();
            }
            return Err(("IDesktopWallpaper::GetMonitorDevicePathCount", status));
        }

        let truncated = count > MAX_MONITORS;
        let shown = core::cmp::min(count, MAX_MONITORS);
        for index in 0..shown {
            let mut monitor_path = core::ptr::null_mut();
            let monitor_status = get_monitor_path(wallpaper, index, &mut monitor_path);
            if monitor_status < 0 || monitor_path.is_null() {
                println!(
                    "[{}] monitor path unavailable: 0x{:08X}",
                    index, monitor_status as u32
                );
                if !monitor_path.is_null() {
                    CoTaskMemFree(monitor_path as *mut c_void);
                }
                continue;
            }

            let mut image_path = core::ptr::null_mut();
            let image_status = get_wallpaper(wallpaper, monitor_path, &mut image_path);
            let monitor = wide_pointer(monitor_path);
            if image_status < 0 {
                println!(
                    "[{}] {} | wallpaper unavailable: 0x{:08X}",
                    index, monitor, image_status as u32
                );
            } else {
                println!("[{}] {} | {}", index, monitor, wide_pointer(image_path));
            }
            if !image_path.is_null() {
                CoTaskMemFree(image_path as *mut c_void);
            }
            CoTaskMemFree(monitor_path as *mut c_void);
        }

        release(wallpaper);
        if uninitialize {
            CoUninitialize();
        }
        Ok((shown, truncated))
    }
}

#[rustbof::main]
fn main() {
    println!("Desktop wallpaper inventory");
    match enumerate_wallpapers() {
        Ok((shown, truncated)) => println!(
            "Monitors shown: {}{}",
            shown,
            if truncated {
                " | monitor limit reached"
            } else {
                ""
            }
        ),
        Err((stage, status)) => {
            println!("{} unavailable: 0x{:08X}", stage, status as u32);
            match registry_wallpaper() {
                Ok(path) => println!(
                    "Current-user registry fallback: {}",
                    if path.is_empty() {
                        "<not configured>"
                    } else {
                        path.as_str()
                    }
                ),
                Err(error) => eprintln!("Current-user registry fallback failed: 0x{:X}", error),
            }
        }
    }
}
