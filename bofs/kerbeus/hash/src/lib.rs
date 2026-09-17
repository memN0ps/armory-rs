//! # Hash BOF
//!
//! Generates Kerberos password hashes (RC4-HMAC, AES128, AES256) from a
//! plaintext password using CDLocateCSystem from cryptdll.dll. AES salts
//! are derived from the domain and username.
//!
//! ## MITRE ATT&CK
//! - T1558 - Steal or Forge Kerberos Tickets
//!
//! ## Arguments
//! - `/password:PASSWORD` - Plaintext password (required)
//! - `/user:USER` - Username for AES salt (optional)
//! - `/domain:DOMAIN` - Domain for AES salt (optional)

#![no_std]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};

const RC4_HMAC: i32 = 23;
const AES128_CTS_HMAC_SHA1: i32 = 17;
const AES256_CTS_HMAC_SHA1: i32 = 18;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct AnsiString {
    length: u16,
    maximum_length: u16,
    buffer: *const u8,
}

type HashPasswordNt6 = unsafe extern "system" fn(
    password: *const UnicodeString,
    salt: *const UnicodeString,
    iterations: u32,
    output: *mut u8,
) -> i32;

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
    initialize: *const c_void,
    encrypt: *const c_void,
    decrypt: *const c_void,
    finish: *const c_void,
    hash_password: HashPasswordNt6,
    random_key: *const c_void,
    control: *const c_void,
    unk0: *const c_void,
    unk1: *const c_void,
    unk2: *const c_void,
}

type CDLocateCSystemFn =
    unsafe extern "system" fn(etype: i32, system: *mut *const KerbEcrypt) -> i32;
type RtlInitAnsiStringFn = unsafe extern "system" fn(dest: *mut AnsiString, src: *const u8);
type RtlAnsiStringToUnicodeStringFn =
    unsafe extern "system" fn(dest: *mut UnicodeString, src: *const AnsiString, alloc: u8) -> i32;
type RtlFreeUnicodeStringFn = unsafe extern "system" fn(s: *mut UnicodeString);

unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
}

struct CryptApi {
    cd_locate_csystem: CDLocateCSystemFn,
    rtl_init_ansi_string: RtlInitAnsiStringFn,
    rtl_ansi_to_unicode: RtlAnsiStringToUnicodeStringFn,
    rtl_free_unicode_string: RtlFreeUnicodeStringFn,
}

fn load_api() -> Option<CryptApi> {
    unsafe {
        let cryptdll = GetModuleHandleA(b"CRYPTDLL\0".as_ptr());
        let cryptdll = if cryptdll.is_null() {
            LoadLibraryA(b"CRYPTDLL\0".as_ptr())
        } else {
            cryptdll
        };
        if cryptdll.is_null() {
            return None;
        }

        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return None;
        }

        let cd_locate = GetProcAddress(cryptdll, b"CDLocateCSystem\0".as_ptr());
        let rtl_init_ansi = GetProcAddress(ntdll, b"RtlInitAnsiString\0".as_ptr());
        let rtl_ansi_to_unicode = GetProcAddress(ntdll, b"RtlAnsiStringToUnicodeString\0".as_ptr());
        let rtl_free_unicode = GetProcAddress(ntdll, b"RtlFreeUnicodeString\0".as_ptr());

        if cd_locate.is_null()
            || rtl_init_ansi.is_null()
            || rtl_ansi_to_unicode.is_null()
            || rtl_free_unicode.is_null()
        {
            return None;
        }

        Some(CryptApi {
            cd_locate_csystem: core::mem::transmute(cd_locate),
            rtl_init_ansi_string: core::mem::transmute(rtl_init_ansi),
            rtl_ansi_to_unicode: core::mem::transmute(rtl_ansi_to_unicode),
            rtl_free_unicode_string: core::mem::transmute(rtl_free_unicode),
        })
    }
}

fn str_to_unicode(api: &CryptApi, s: &str) -> Option<UnicodeString> {
    unsafe {
        let mut cstr = Vec::with_capacity(s.len() + 1);
        cstr.extend_from_slice(s.as_bytes());
        cstr.push(0);

        let mut ansi = core::mem::zeroed::<AnsiString>();
        (api.rtl_init_ansi_string)(&mut ansi, cstr.as_ptr());

        let mut unicode = core::mem::zeroed::<UnicodeString>();
        let status = (api.rtl_ansi_to_unicode)(&mut unicode, &ansi, 1);
        if status >= 0 { Some(unicode) } else { None }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = (b >> 4) & 0xf;
        let lo = b & 0xf;
        hex.push(if hi < 10 {
            (b'0' + hi) as char
        } else {
            (b'a' + hi - 10) as char
        });
        hex.push(if lo < 10 {
            (b'0' + lo) as char
        } else {
            (b'a' + lo - 10) as char
        });
    }
    hex
}

fn get_key(api: &CryptApi, etype: i32, password: &str, salt_str: &str) -> Option<Vec<u8>> {
    unsafe {
        let mut csystem: *const KerbEcrypt = core::ptr::null();
        let status = (api.cd_locate_csystem)(etype, &mut csystem);
        if status < 0 || csystem.is_null() {
            return None;
        }

        let key_size = (*csystem).key_size as usize;
        let mut key = vec![0u8; key_size];

        let mut pw_unicode = str_to_unicode(api, password)?;
        let mut salt_unicode = str_to_unicode(api, salt_str)?;

        let result = ((*csystem).hash_password)(&pw_unicode, &salt_unicode, 4096, key.as_mut_ptr());

        (api.rtl_free_unicode_string)(&mut pw_unicode);
        (api.rtl_free_unicode_string)(&mut salt_unicode);

        if result >= 0 { Some(key) } else { None }
    }
}

fn build_aes_salt(domain: &str, username: &str) -> String {
    let is_machine = username.ends_with('$');
    if is_machine {
        let name_no_dollar = &username[..username.len() - 1];
        let mut salt = String::new();
        for c in domain.chars() {
            salt.push(c.to_ascii_uppercase());
        }
        salt.push_str("host");
        for c in name_no_dollar.chars() {
            salt.push(c.to_ascii_lowercase());
        }
        salt.push('.');
        for c in domain.chars() {
            salt.push(c.to_ascii_lowercase());
        }
        salt
    } else {
        let mut salt = String::new();
        for c in domain.chars() {
            salt.push(c.to_ascii_uppercase());
        }
        for c in username.chars() {
            salt.push(c);
        }
        salt
    }
}

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    let mut search = params;
    while let Some(pos) = search.find(name) {
        let after = &search[pos + name.len()..];
        let end = after.find(' ').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() {
            return Some(value);
        }
        search = after;
    }
    None
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let password = get_param(&params, "/password:");
    let user = get_param(&params, "/user:");
    let domain = get_param(&params, "/domain:");

    let password = match password {
        Some(p) => p,
        None => {
            eprintln!("[X] /password:X must be supplied!");
            return;
        }
    };

    println!("[*] Action: Calculate Password Hash(es)\n");
    println!("[*] Input Password           : {}", password);

    if let (Some(u), Some(d)) = (user, domain) {
        println!("[*] Input Username           : {}", u);
        println!("[*] Input Domain             : {}", d);
    }

    let api = match load_api() {
        Some(a) => a,
        None => {
            eprintln!("[X] Failed to load crypto modules");
            return;
        }
    };

    if let Some(key) = get_key(&api, RC4_HMAC, password, "") {
        println!("[*]     rc4_hmac             : {}", bytes_to_hex(&key));
    } else {
        eprintln!("[X] Failed to generate RC4-HMAC hash");
    }

    if let (Some(u), Some(d)) = (user, domain) {
        let salt = build_aes_salt(d, u);

        if let Some(key) = get_key(&api, AES128_CTS_HMAC_SHA1, password, &salt) {
            println!("[*]     aes128_cts_hmac_sha1 : {}", bytes_to_hex(&key));
        } else {
            eprintln!("[X] Failed to generate AES128 hash");
        }

        if let Some(key) = get_key(&api, AES256_CTS_HMAC_SHA1, password, &salt) {
            println!("[*]     aes256_cts_hmac_sha1 : {}", bytes_to_hex(&key));
        } else {
            eprintln!("[X] Failed to generate AES256 hash");
        }
    }
}
