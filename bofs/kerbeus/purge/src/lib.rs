//! # Purge BOF
//!
//! Purges all cached Kerberos tickets from the current logon session
//! via LsaCallAuthenticationPackage with KerbPurgeTicketCacheMessage.
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/luid:LUID` - Target logon session LUID (optional, requires SYSTEM)

#![no_std]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Threading::*;

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    if let Some(pos) = params.find(name) {
        let after = &params[pos + name.len()..];
        let end = after.find(' ').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() { return Some(value); }
    }
    None
}

fn hex_to_u32(s: &str) -> Option<u32> {
    let s = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };
    let mut result = 0u32;
    for c in s.bytes() {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(digit as u32)?;
    }
    Some(result)
}

fn get_current_token() -> HANDLE {
    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &mut token) == 0 {
            if token.is_null() && GetLastError() == ERROR_NO_TOKEN {
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return core::ptr::null_mut();
                }
            }
        }
        token
    }
}

fn get_current_luid(token: HANDLE) -> LUID {
    unsafe {
        let mut stats = core::mem::zeroed::<TOKEN_STATISTICS>();
        let mut size = 0u32;
        if GetTokenInformation(
            token,
            TokenStatistics,
            &mut stats as *mut _ as *mut c_void,
            core::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut size,
        ) == 0
        {
            return LUID { LowPart: 0, HighPart: 0 };
        }
        stats.AuthenticationId
    }
}

fn is_system() -> bool {
    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut token) == 0 {
            if GetLastError() == ERROR_NO_TOKEN {
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return false;
                }
            } else {
                return false;
            }
        }

        let mut buf = [0u8; 256];
        let mut size = 0u32;
        if GetTokenInformation(
            token, TokenUser, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut size,
        ) == 0
        {
            CloseHandle(token);
            return false;
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let nt_authority = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 5] };
        let mut system_sid: PSID = core::ptr::null_mut();

        if AllocateAndInitializeSid(
            &nt_authority, 1, 18, 0, 0, 0, 0, 0, 0, 0, &mut system_sid,
        ) == 0
        {
            CloseHandle(token);
            return false;
        }

        let result = EqualSid(token_user.User.Sid, system_sid) != 0;
        FreeSid(system_sid);
        CloseHandle(token);
        result
    }
}

fn get_lsa_handle(high_integrity: bool) -> Option<HANDLE> {
    unsafe {
        let mut handle: HANDLE = core::ptr::null_mut();
        let status = if high_integrity {
            let lsa_string = LSA_STRING {
                Length: 8,
                MaximumLength: 9,
                Buffer: b"Winlogon\0".as_ptr() as *mut u8,
            };
            let mut mode = 0u32;
            LsaRegisterLogonProcess(&lsa_string, &mut handle, &mut mode)
        } else {
            LsaConnectUntrusted(&mut handle)
        };
        if status >= 0 { Some(handle) } else { None }
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("\n[*] Action: Purge Tickets\n");

    let mut luid_arg: Option<&str> = None;
    let params;

    if len > 0 {
        let mut parser = DataParser::new(args, len);
        params = String::from(parser.get_str());
        luid_arg = get_param(&params, "/luid:");
    }

    let token = get_current_token();
    let current_luid = get_current_luid(token);
    let high_integrity = is_system();

    let target_luid = if let Some(luid_str) = luid_arg {
        match hex_to_u32(luid_str) {
            Some(v) if v > 0 => LUID { LowPart: v, HighPart: 0 },
            _ => {
                eprintln!("[X] Invalid LUID");
                return;
            }
        }
    } else {
        current_luid
    };

    if !high_integrity && current_luid.LowPart != target_luid.LowPart {
        eprintln!("[X] You need to be in SYSTEM integrity.");
        return;
    }

    let hlsa = match get_lsa_handle(high_integrity) {
        Some(h) => h,
        None => {
            eprintln!("[X] Failed to get LSA handle");
            return;
        }
    };

    unsafe {
        let krb_auth = LSA_STRING {
            Length: 8,
            MaximumLength: 9,
            Buffer: b"kerberos\0".as_ptr() as *mut u8,
        };
        let mut auth_package = 0u32;
        if LsaLookupAuthenticationPackage(hlsa, &krb_auth, &mut auth_package) < 0 {
            eprintln!("[X] Failed to lookup Kerberos auth package");
            LsaDeregisterLogonProcess(hlsa);
            return;
        }

        let mut purge_request = core::mem::zeroed::<KERB_PURGE_TKT_CACHE_REQUEST>();
        purge_request.MessageType = KerbPurgeTicketCacheMessage;
        purge_request.LogonId = if high_integrity { target_luid } else { LUID { LowPart: 0, HighPart: 0 } };

        let mut response_ptr: *mut c_void = core::ptr::null_mut();
        let mut response_size = 0u32;
        let mut protocol_status = 0i32;

        let status = LsaCallAuthenticationPackage(
            hlsa,
            auth_package,
            &purge_request as *const _ as *const c_void,
            core::mem::size_of::<KERB_PURGE_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );

        if status < 0 || protocol_status < 0 {
            eprintln!("[X] Tickets not purged.");
        } else {
            println!("[+] Successfully purged tickets.");
        }

        LsaDeregisterLogonProcess(hlsa);
    }
}
