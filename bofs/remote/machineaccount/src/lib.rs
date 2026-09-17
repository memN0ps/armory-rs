//! # Machine Account BOF
//!
//! Queries, creates, or deletes one exact Active Directory machine account on
//! a named domain controller through NetAPI. Creation refuses to overwrite an
//! existing account. Deletion is a separate explicit rollback action.
//!
//! ## MITRE ATT&CK
//! - T1136.002 - Create Account: Domain Account
//!
//! ## Arguments
//! - `str`: `query`, `add`, or `delete`.
//! - `str`: Domain controller name, normally prefixed with `\\`.
//! - `str`: Machine account name ending in `$`.
//! - `str`: Password for `add`; pass an empty string for `query` and `delete`.

#![no_std]

use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::{eprintln, println};

#[repr(C)]
struct UserInfo1 {
    name: *mut u16,
    password: *mut u16,
    password_age: u32,
    privilege: u32,
    home_directory: *mut u16,
    comment: *mut u16,
    flags: u32,
    script_path: *mut u16,
}

unsafe extern "system" {
    fn NetUserAdd(server: *const u16, level: u32, buffer: *const u8, error: *mut u32) -> u32;
    fn NetUserDel(server: *const u16, user: *const u16) -> u32;
    fn NetUserGetInfo(
        server: *const u16,
        user: *const u16,
        level: u32,
        buffer: *mut *mut u8,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut c_void) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const NERR_USER_NOT_FOUND: u32 = 2221;
const USER_PRIV_USER: u32 = 1;
const UF_SCRIPT: u32 = 0x0001;
const UF_WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;

struct PackedArgs<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> PackedArgs<'a> {
    fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < 4 {
            return None;
        }
        let declared = u32::from_le_bytes(buffer[..4].try_into().ok()?) as usize;
        if declared != buffer.len() - 4 {
            return None;
        }
        Some(Self { buffer, offset: 4 })
    }

    fn read_string(&mut self, maximum: usize, allow_empty: bool) -> Option<&'a str> {
        let length_end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..length_end)?.try_into().ok()?) as usize;
        self.offset = length_end;
        if length == 0 || length > maximum + 1 {
            return None;
        }
        let value_end = self.offset.checked_add(length)?;
        let value = self.buffer.get(self.offset..value_end)?;
        self.offset = value_end;
        if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
            return None;
        }
        let value = core::str::from_utf8(&value[..length - 1]).ok()?;
        if !allow_empty && value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

fn wide_z(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn validate_account(account: &str) -> bool {
    account.len() >= 2
        && account.len() <= 20
        && account.ends_with('$')
        && !account[..account.len() - 1]
            .bytes()
            .any(|byte| byte <= b' ' || b"/\\[]:;|=,+*?<>\"".contains(&byte))
}

fn query(server: &[u16], account: &[u16]) -> Result<Option<u32>, u32> {
    let mut buffer = core::ptr::null_mut();
    let status = unsafe { NetUserGetInfo(server.as_ptr(), account.as_ptr(), 1, &mut buffer) };
    if status == NERR_USER_NOT_FOUND {
        return Ok(None);
    }
    if status != NERR_SUCCESS || buffer.is_null() {
        return Err(status);
    }
    let flags = unsafe { (*(buffer as *const UserInfo1)).flags };
    unsafe { NetApiBufferFree(buffer as *mut c_void) };
    Ok(Some(flags))
}

fn add(server: &[u16], account: &str, password: &str) -> Result<(), (&'static str, u32)> {
    let account_wide = wide_z(account);
    match query(server, &account_wide) {
        Ok(Some(_)) => return Err(("account already exists; refusing overwrite", 0)),
        Ok(None) => {}
        Err(status) => return Err(("preflight query", status)),
    }

    let password_wide = wide_z(password);
    let mut info = UserInfo1 {
        name: account_wide.as_ptr() as *mut u16,
        password: password_wide.as_ptr() as *mut u16,
        password_age: 0,
        privilege: USER_PRIV_USER,
        home_directory: core::ptr::null_mut(),
        comment: core::ptr::null_mut(),
        flags: UF_SCRIPT | UF_WORKSTATION_TRUST_ACCOUNT,
        script_path: core::ptr::null_mut(),
    };
    let mut parameter_error = 0u32;
    let status = unsafe {
        NetUserAdd(
            server.as_ptr(),
            1,
            &mut info as *mut UserInfo1 as *const u8,
            &mut parameter_error,
        )
    };
    if status != NERR_SUCCESS {
        return Err(("NetUserAdd", status));
    }

    match query(server, &account_wide) {
        Ok(Some(flags)) if flags & UF_WORKSTATION_TRUST_ACCOUNT != 0 => Ok(()),
        Ok(_) => Err(("post-create verification", 13)),
        Err(status) => Err(("post-create query", status)),
    }
}

fn delete(server: &[u16], account: &str) -> Result<(), (&'static str, u32)> {
    let account_wide = wide_z(account);
    match query(server, &account_wide) {
        Ok(None) => return Err(("account does not exist", NERR_USER_NOT_FOUND)),
        Ok(Some(flags)) if flags & UF_WORKSTATION_TRUST_ACCOUNT != 0 => {}
        Ok(Some(_)) => return Err(("target is not a workstation trust account", 13)),
        Err(status) => return Err(("pre-delete query", status)),
    }

    let status = unsafe { NetUserDel(server.as_ptr(), account_wide.as_ptr()) };
    if status != NERR_SUCCESS {
        return Err(("NetUserDel", status));
    }
    match query(server, &account_wide) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(("post-delete verification", 13)),
        Err(status) => Err(("post-delete query", status)),
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let action = parser.read_string(16, false)?;
            let server = parser.read_string(256, false)?;
            let account = parser.read_string(20, false)?;
            let password = parser.read_string(256, true)?;
            parser
                .finished()
                .then_some((action, server, account, password))
        })
    };

    match parsed {
        None => eprintln!(
            "Usage: machineaccount <query|add|delete> <\\\\domain-controller> <name$> <password_or_empty>"
        ),
        Some((_action, _server, account, _password)) if !validate_account(account) => {
            eprintln!("Machine account must be 2-20 characters and end in $.")
        }
        Some((action, server, account, password)) => {
            let server_wide = wide_z(server);
            if action.eq_ignore_ascii_case("query") {
                match query(&server_wide, &wide_z(account)) {
                    Ok(Some(flags)) => println!(
                        "Machine account {} exists | workstation-trust={} | flags=0x{:08X}",
                        account,
                        if flags & UF_WORKSTATION_TRUST_ACCOUNT != 0 {
                            "yes"
                        } else {
                            "no"
                        },
                        flags
                    ),
                    Ok(None) => println!("Machine account {} was not found.", account),
                    Err(status) => eprintln!("NetUserGetInfo failed: 0x{:X}", status),
                }
            } else if action.eq_ignore_ascii_case("add") {
                if password.is_empty() {
                    eprintln!("A non-empty password is required for add.");
                } else {
                    match add(&server_wide, account, password) {
                        Ok(()) => println!(
                            "Machine account {} created and verified. Run the matching delete action to roll it back.",
                            account
                        ),
                        Err((stage, 0)) => eprintln!("{}", stage),
                        Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
                    }
                }
            } else if action.eq_ignore_ascii_case("delete") {
                match delete(&server_wide, account) {
                    Ok(()) => println!("Machine account {} deleted and verified absent.", account),
                    Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
                }
            } else {
                eprintln!("Unsupported action. Use query, add, or delete.");
            }
        }
    }
}
