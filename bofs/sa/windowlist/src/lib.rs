#![no_std]

use rustbof::println;
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextA, IsWindowVisible};
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};

unsafe extern "system" fn enum_callback(hwnd: HWND, _lparam: LPARAM) -> BOOL {
    let mut name = [0u8; 128];
    let len = GetWindowTextA(hwnd, name.as_mut_ptr(), 127);
    if len > 0 && name[0] != 0 {
        let title = core::str::from_utf8(&name[..len as usize]).unwrap_or("");
        let vis = if IsWindowVisible(hwnd) != 0 { "Visible" } else { "Hidden" };
        println!("{:<40} : {}", title, vis);
    }
    1
}

#[rustbof::main]
fn main() {
    unsafe {
        EnumWindows(Some(enum_callback), 0);
    }
}
