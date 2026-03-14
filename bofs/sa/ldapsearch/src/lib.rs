//! # LDAP Search BOF
//!
//! Performs LDAP searches against Active Directory using the Windows LDAP API.
//! Supports custom filters, attribute selection, auto-detection of the domain
//! controller via DsGetDcNameA, and automatic base DN discovery via rootDSE.
//!
//! ## MITRE ATT&CK
//! - T1087.002 - Account Discovery: Domain Account
//!
//! ## Arguments
//! - `str`: LDAP filter (e.g., `(objectClass=user)`)
//! - `str`: Attributes comma-separated (e.g., `sAMAccountName,distinguishedName`) or `*` for all
//! - `str`: Domain controller hostname (empty = auto-detect via DsGetDcNameA)
//! - `int`: Result limit (0 = unlimited)

#![no_std]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
const LDAP_PORT: u32 = 389;
const LDAP_SCOPE_SUBTREE: u32 = 2;
const LDAP_SCOPE_BASE: u32 = 0;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const LDAP_OPT_REFERRALS: i32 = 0x08;
const LDAP_SUCCESS: u32 = 0;

const DS_RETURN_DNS_NAME: u32 = 0x40000000;
unsafe extern "C" {
    fn ldap_initA(host: *const u8, port: u32) -> *mut core::ffi::c_void;
    fn ldap_set_optionA(
        ld: *mut core::ffi::c_void,
        option: i32,
        value: *const core::ffi::c_void,
    ) -> u32;
    fn ldap_bind_sA(
        ld: *mut core::ffi::c_void,
        dn: *const u8,
        cred: *const u8,
        method: u32,
    ) -> u32;
    fn ldap_search_sA(
        ld: *mut core::ffi::c_void,
        base: *const u8,
        scope: u32,
        filter: *const u8,
        attrs: *const *const u8,
        attrsonly: u32,
        res: *mut *mut core::ffi::c_void,
    ) -> u32;
    fn ldap_count_entries(
        ld: *mut core::ffi::c_void,
        res: *mut core::ffi::c_void,
    ) -> u32;
    fn ldap_first_entry(
        ld: *mut core::ffi::c_void,
        res: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn ldap_next_entry(
        ld: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn ldap_first_attributeA(
        ld: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
        ber: *mut *mut core::ffi::c_void,
    ) -> *mut u8;
    fn ldap_next_attributeA(
        ld: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
        ber: *mut core::ffi::c_void,
    ) -> *mut u8;
    fn ldap_get_valuesA(
        ld: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
        attr: *const u8,
    ) -> *mut *mut u8;
    fn ldap_value_freeA(vals: *mut *mut u8) -> u32;
    fn ldap_memfreeA(block: *mut u8);
    fn ldap_msgfree(res: *mut core::ffi::c_void) -> u32;
    fn ldap_unbind(ld: *mut core::ffi::c_void) -> u32;
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
    fn DsGetDcNameA(
        computer: *const u8,
        domain: *const u8,
        guid: *mut core::ffi::c_void,
        site: *const u8,
        flags: u32,
        info: *mut *mut DomainControllerInfoA,
    ) -> u32;
}

unsafe extern "system" {
    fn NetApiBufferFree(buffer: *const core::ffi::c_void) -> u32;
}
unsafe fn cstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(slice).into_owned()
}

fn to_cstr_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}
unsafe fn get_default_naming_context(ld: *mut core::ffi::c_void) -> Option<String> {
    let base = b"\0";
    let filter = b"(objectClass=*)\0";
    let attr_name = b"defaultNamingContext\0";
    let attrs: [*const u8; 2] = [attr_name.as_ptr(), core::ptr::null()];

    let mut res: *mut core::ffi::c_void = core::ptr::null_mut();
    let rc = ldap_search_sA(
        ld,
        base.as_ptr(),
        LDAP_SCOPE_BASE,
        filter.as_ptr(),
        attrs.as_ptr(),
        0,
        &mut res,
    );

    if rc != LDAP_SUCCESS || res.is_null() {
        return None;
    }

    let entry = ldap_first_entry(ld, res);
    if entry.is_null() {
        ldap_msgfree(res);
        return None;
    }

    let vals = ldap_get_valuesA(ld, entry, attr_name.as_ptr());
    if vals.is_null() {
        ldap_msgfree(res);
        return None;
    }

    let first = *vals;
    let result = if !first.is_null() {
        Some(cstr_to_string(first))
    } else {
        None
    };

    ldap_value_freeA(vals);
    ldap_msgfree(res);
    result
}

unsafe fn print_entry(ld: *mut core::ffi::c_void, entry: *mut core::ffi::c_void) {
    let mut ber: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut attr_ptr = ldap_first_attributeA(ld, entry, &mut ber);

    while !attr_ptr.is_null() {
        let attr_name = cstr_to_string(attr_ptr);

        let vals = ldap_get_valuesA(ld, entry, attr_ptr);
        if !vals.is_null() {
            let mut i = 0usize;
            loop {
                let val = *vals.add(i);
                if val.is_null() {
                    break;
                }
                let val_str = cstr_to_string(val);
                println!("    {}: {}", attr_name, val_str);
                i += 1;
            }
            ldap_value_freeA(vals);
        } else {
            println!("    {}: <no values>", attr_name);
        }

        ldap_memfreeA(attr_ptr);
        attr_ptr = ldap_next_attributeA(ld, entry, ber);
    }
}
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let filter = String::from(parser.get_str());
    let attrs_str = String::from(parser.get_str());
    let dc_host_arg = String::from(parser.get_str());
    let result_limit = parser.get_int() as u32;

    if filter.is_empty() {
        eprintln!("Error: LDAP filter is required.");
        return;
    }

    unsafe {
        let dc_host: String;
        let mut dc_info_ptr: *mut DomainControllerInfoA = core::ptr::null_mut();

        if dc_host_arg.is_empty() {
            let rc = DsGetDcNameA(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                DS_RETURN_DNS_NAME,
                &mut dc_info_ptr,
            );

            if rc != 0 || dc_info_ptr.is_null() {
                eprintln!("DsGetDcNameA failed with error: {}", rc);
                return;
            }

            let raw_name = cstr_to_string((*dc_info_ptr).dc_name);
            dc_host = if raw_name.starts_with("\\\\") {
                String::from(&raw_name[2..])
            } else {
                raw_name
            };
            println!("Auto-detected DC: {}", dc_host);
        } else {
            dc_host = dc_host_arg;
        }

        let dc_cstr = to_cstr_bytes(&dc_host);
        let ld = ldap_initA(dc_cstr.as_ptr(), LDAP_PORT);
        if ld.is_null() {
            eprintln!("ldap_initA failed for host '{}'", dc_host);
            if !dc_info_ptr.is_null() {
                NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
            }
            return;
        }

        let off: u32 = 0;
        ldap_set_optionA(
            ld,
            LDAP_OPT_REFERRALS,
            &off as *const u32 as *const core::ffi::c_void,
        );

        let rc = ldap_bind_sA(ld, core::ptr::null(), core::ptr::null(), LDAP_AUTH_NEGOTIATE);
        if rc != LDAP_SUCCESS {
            eprintln!("ldap_bind_sA failed with error: {}", rc);
            ldap_unbind(ld);
            if !dc_info_ptr.is_null() {
                NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
            }
            return;
        }

        let base_dn = match get_default_naming_context(ld) {
            Some(dn) => dn,
            None => {
                eprintln!("Failed to retrieve defaultNamingContext from rootDSE.");
                ldap_unbind(ld);
                if !dc_info_ptr.is_null() {
                    NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
                }
                return;
            }
        };
        println!("Base DN: {}", base_dn);

        let attr_cstrs: Vec<Vec<u8>>;
        let attr_ptrs: Vec<*const u8>;

        if attrs_str == "*" || attrs_str.is_empty() {
            attr_cstrs = Vec::new();
            attr_ptrs = vec![core::ptr::null()];
        } else {
            attr_cstrs = attrs_str
                .split(',')
                .map(|a| to_cstr_bytes(a.trim()))
                .collect();
            let mut ptrs: Vec<*const u8> = attr_cstrs.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(core::ptr::null()); // null-terminate the array
            attr_ptrs = ptrs;
        }

        let attrs_param = if attrs_str == "*" || attrs_str.is_empty() {
            core::ptr::null()
        } else {
            attr_ptrs.as_ptr()
        };

        let filter_cstr = to_cstr_bytes(&filter);
        let base_cstr = to_cstr_bytes(&base_dn);

        let mut search_res: *mut core::ffi::c_void = core::ptr::null_mut();
        let rc = ldap_search_sA(
            ld,
            base_cstr.as_ptr(),
            LDAP_SCOPE_SUBTREE,
            filter_cstr.as_ptr(),
            attrs_param,
            0,
            &mut search_res,
        );

        if rc != LDAP_SUCCESS {
            eprintln!("ldap_search_sA failed with error: {}", rc);
            ldap_unbind(ld);
            if !dc_info_ptr.is_null() {
                NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
            }
            return;
        }

        let total = ldap_count_entries(ld, search_res);
        println!("Filter: {}", filter);
        println!("Results: {}\n", total);

        let mut entry = ldap_first_entry(ld, search_res);
        let mut count: u32 = 0;

        while !entry.is_null() {
            if result_limit > 0 && count >= result_limit {
                println!("(result limit {} reached)", result_limit);
                break;
            }

            println!("  [Entry {}]", count + 1);
            print_entry(ld, entry);
            println!();

            count += 1;
            entry = ldap_next_entry(ld, entry);
        }

        println!("Displayed {} of {} entries.", count, total);

        if !search_res.is_null() {
            ldap_msgfree(search_res);
        }
        ldap_unbind(ld);
        if !dc_info_ptr.is_null() {
            NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
        }
    }
}
