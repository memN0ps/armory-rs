//! # ADCS Enumeration via COM BOF
//!
//! Enumerates Active Directory Certificate Services (AD CS) configuration
//! using the ICertConfig2 COM interface to discover certificate authorities.
//!
//! ## MITRE ATT&CK
//! - T1649 - Steal or Forge Authentication Certificates
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::string::String;
use rustbof::{eprintln, println};
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut core::ffi::c_void, coinit: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        clsid: *const [u8; 16],
        outer: *mut core::ffi::c_void,
        ctx: u32,
        iid: *const [u8; 16],
        ppv: *mut *mut core::ffi::c_void,
    ) -> i32;
    fn SysFreeString(bstr: *mut u16);
}

const COINIT_MULTITHREADED: u32 = 0;
const CLSCTX_ALL: u32 = 23;
const S_OK: i32 = 0;
const S_FALSE: i32 = 1;

const CLSID_CCERTCONFIG: [u8; 16] = [
    0x38, 0xCE, 0x2F, 0x37, // Data1: 372FCE38 (LE)
    0x24, 0x43, // Data2: 4324 (LE)
    0xD0, 0x11, // Data3: 11D0 (LE)
    0x88, 0x10, // Data4[0..2]
    0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C, // Data4[2..8]
];

const IID_ICERTCONFIG2: [u8; 16] = [
    0xDE, 0xED, 0x18, 0x7A, // Data1: 7A18EDDE (LE)
    0x78, 0x7E, // Data2: 7E78 (LE)
    0x63, 0x41, // Data3: 4163 (LE)
    0x8D, 0xED, // Data4[0..2]
    0x78, 0xE2, 0xC9, 0xCE, 0xE9, 0x24, // Data4[2..8]
];
#[repr(C)]
struct ICertConfig2Vtbl {
    query_interface: *const core::ffi::c_void,
    add_ref: *const core::ffi::c_void,
    release: unsafe extern "system" fn(this: *mut core::ffi::c_void) -> u32,
    _dispatch: [*const core::ffi::c_void; 4],
    reset:
        unsafe extern "system" fn(this: *mut core::ffi::c_void, index: i32, count: *mut i32) -> i32,
    next: unsafe extern "system" fn(this: *mut core::ffi::c_void, index: *mut i32) -> i32,
    get_field: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        field: *const u16,
        value: *mut *mut u16,
    ) -> i32,
    get_config: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        flags: i32,
        config: *mut *mut u16,
    ) -> i32,
}

#[repr(C)]
struct ComObject {
    vtbl: *const ICertConfig2Vtbl,
}
fn to_wide_bstr(s: &str) -> alloc::vec::Vec<u16> {
    let mut v: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn bstr_to_string(bstr: *mut u16) -> String {
    if bstr.is_null() {
        return String::from("(null)");
    }
    unsafe {
        let mut len = 0;
        while *bstr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(bstr, len);
        String::from_utf16_lossy(slice)
    }
}
#[rustbof::main]
fn main() {
    println!("=== ADCS CA Enumeration via ICertConfig2 COM (T1649) ===");
    println!();

    unsafe {
        let hr = CoInitializeEx(core::ptr::null_mut(), COINIT_MULTITHREADED);
        if hr < 0 {
            eprintln!("CoInitializeEx failed: 0x{:08X}", hr as u32);
            return;
        }

        let mut p_config: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_CCERTCONFIG,
            core::ptr::null_mut(),
            CLSCTX_ALL,
            &IID_ICERTCONFIG2,
            &mut p_config,
        );
        if hr < 0 || p_config.is_null() {
            eprintln!("CoCreateInstance(ICertConfig2) failed: 0x{:08X}", hr as u32);
            CoUninitialize();
            return;
        }

        let obj = p_config as *mut ComObject;
        let vtbl = &*(*obj).vtbl;

        let mut count: i32 = 0;
        let hr = (vtbl.reset)(p_config, 0, &mut count);
        if hr < 0 {
            eprintln!("ICertConfig2::Reset failed: 0x{:08X}", hr as u32);
            (vtbl.release)(p_config);
            CoUninitialize();
            return;
        }

        println!("Found {} CA configuration(s)", count);
        println!();

        let field_cn = to_wide_bstr("CommonName");
        let field_config = to_wide_bstr("Config");
        let field_server = to_wide_bstr("Server");
        let field_san_name = to_wide_bstr("SanitizedName");
        let field_org_unit = to_wide_bstr("OrgUnit");
        let field_country = to_wide_bstr("Country");

        let mut ca_idx: u32 = 0;
        loop {
            let mut index: i32 = 0;
            let hr = (vtbl.next)(p_config, &mut index);
            if hr == S_FALSE || hr < 0 {
                break;
            }

            ca_idx += 1;

            let mut val: *mut u16 = core::ptr::null_mut();
            let cn = if (vtbl.get_field)(p_config, field_cn.as_ptr(), &mut val) == S_OK {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut val: *mut u16 = core::ptr::null_mut();
            let config = if (vtbl.get_field)(p_config, field_config.as_ptr(), &mut val) == S_OK {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut val: *mut u16 = core::ptr::null_mut();
            let server = if (vtbl.get_field)(p_config, field_server.as_ptr(), &mut val) == S_OK {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut val: *mut u16 = core::ptr::null_mut();
            let san_name = if (vtbl.get_field)(p_config, field_san_name.as_ptr(), &mut val) == S_OK
            {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut val: *mut u16 = core::ptr::null_mut();
            let org_unit = if (vtbl.get_field)(p_config, field_org_unit.as_ptr(), &mut val) == S_OK
            {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(none)")
            };

            let mut val: *mut u16 = core::ptr::null_mut();
            let country = if (vtbl.get_field)(p_config, field_country.as_ptr(), &mut val) == S_OK {
                let s = bstr_to_string(val);
                SysFreeString(val);
                s
            } else {
                String::from("(none)")
            };

            println!("[CA {}] {}", ca_idx, cn);
            println!("  Config:         {}", config);
            println!("  Server:         {}", server);
            println!("  Sanitized Name: {}", san_name);
            println!("  Org Unit:       {}", org_unit);
            println!("  Country:        {}", country);
            println!();
        }

        if ca_idx == 0 {
            println!("No Certificate Authorities found.");
        }

        (vtbl.release)(p_config);
        CoUninitialize();
    }

    println!("=== ADCS COM enumeration complete ===");
}
