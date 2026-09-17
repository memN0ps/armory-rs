//! # LDAP Security Check BOF
//!
//! Checks LDAP signing and channel binding requirements on a domain controller.
//! Attempts unauthenticated simple binds to determine if LDAP signing is enforced,
//! and tests LDAPS (port 636) connectivity for channel binding assessment.
//!
//! ## MITRE ATT&CK
//! - T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
//!
//! ## Arguments
//! - `str`: Domain controller hostname (empty = auto-detect via DsGetDcNameA)

#![no_std]

use alloc::string::String;
use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
const LDAP_PORT: u32 = 389;
const LDAPS_PORT: u32 = 636;
const LDAP_SCOPE_BASE: u32 = 0;
const LDAP_AUTH_SIMPLE: u32 = 0x80;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const LDAP_OPT_REFERRALS: i32 = 0x08;
const LDAP_OPT_SSL: i32 = 0x0A;
const LDAP_SUCCESS: u32 = 0;

const DS_RETURN_DNS_NAME: u32 = 0x40000000;
unsafe extern "C" {
    fn ldap_initA(host: *const u8, port: u32) -> *mut core::ffi::c_void;
    fn ldap_set_optionA(
        ld: *mut core::ffi::c_void,
        option: i32,
        value: *const core::ffi::c_void,
    ) -> u32;
    fn ldap_bind_sA(ld: *mut core::ffi::c_void, dn: *const u8, cred: *const u8, method: u32)
    -> u32;
    fn ldap_search_sA(
        ld: *mut core::ffi::c_void,
        base: *const u8,
        scope: u32,
        filter: *const u8,
        attrs: *const *const u8,
        attrsonly: u32,
        res: *mut *mut core::ffi::c_void,
    ) -> u32;
    fn ldap_first_entry(
        ld: *mut core::ffi::c_void,
        res: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn ldap_get_valuesA(
        ld: *mut core::ffi::c_void,
        entry: *mut core::ffi::c_void,
        attr: *const u8,
    ) -> *mut *mut u8;
    fn ldap_value_freeA(vals: *mut *mut u8) -> u32;
    fn ldap_msgfree(res: *mut core::ffi::c_void) -> u32;
    fn ldap_unbind(ld: *mut core::ffi::c_void) -> u32;
    fn LdapGetLastError() -> u32;
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
    unsafe {
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
}

fn to_cstr_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let dc_host_arg = String::from(parser.get_str());

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

        println!("\n=== LDAP Security Check: {} ===\n", dc_host);

        println!(
            "[*] Testing LDAP signing requirement (port {})...",
            LDAP_PORT
        );

        let ld = ldap_initA(dc_cstr.as_ptr(), LDAP_PORT);
        if ld.is_null() {
            eprintln!("[-] ldap_initA failed for host '{}'", dc_host);
        } else {
            let off: u32 = 0;
            ldap_set_optionA(
                ld,
                LDAP_OPT_REFERRALS,
                &off as *const u32 as *const core::ffi::c_void,
            );

            let rc = ldap_bind_sA(ld, core::ptr::null(), core::ptr::null(), LDAP_AUTH_SIMPLE);

            if rc == LDAP_SUCCESS {
                println!("[!] LDAP signing NOT required - VULNERABLE");
                println!("    Simple bind succeeded without signing.");
                println!("    An attacker could relay LDAP credentials.");
            } else {
                println!("[+] LDAP signing IS required - SECURE");
                println!("    Simple bind failed with error: {} (0x{:X})", rc, rc);
                println!("    LDAP signing is enforced on this DC.");
            }
            ldap_unbind(ld);
        }

        println!("\n[*] Testing authenticated LDAP bind (NEGOTIATE)...");

        let ld2 = ldap_initA(dc_cstr.as_ptr(), LDAP_PORT);
        if ld2.is_null() {
            eprintln!("[-] ldap_initA failed for authenticated test");
        } else {
            let off: u32 = 0;
            ldap_set_optionA(
                ld2,
                LDAP_OPT_REFERRALS,
                &off as *const u32 as *const core::ffi::c_void,
            );

            let rc = ldap_bind_sA(
                ld2,
                core::ptr::null(),
                core::ptr::null(),
                LDAP_AUTH_NEGOTIATE,
            );
            if rc == LDAP_SUCCESS {
                println!("[+] Authenticated LDAP bind succeeded.");

                let base = b"\0";
                let filter = b"(objectClass=*)\0";
                let attr_name = b"supportedSASLMechanisms\0";
                let attrs: [*const u8; 2] = [attr_name.as_ptr(), core::ptr::null()];

                let mut res: *mut core::ffi::c_void = core::ptr::null_mut();
                let src = ldap_search_sA(
                    ld2,
                    base.as_ptr(),
                    LDAP_SCOPE_BASE,
                    filter.as_ptr(),
                    attrs.as_ptr(),
                    0,
                    &mut res,
                );

                if src == LDAP_SUCCESS && !res.is_null() {
                    let entry = ldap_first_entry(ld2, res);
                    if !entry.is_null() {
                        let vals = ldap_get_valuesA(ld2, entry, attr_name.as_ptr());
                        if !vals.is_null() {
                            println!("    Supported SASL mechanisms:");
                            let mut i = 0usize;
                            loop {
                                let val = *vals.add(i);
                                if val.is_null() {
                                    break;
                                }
                                let val_str = cstr_to_string(val);
                                println!("      - {}", val_str);
                                i += 1;
                            }
                            ldap_value_freeA(vals);
                        }
                    }
                    ldap_msgfree(res);
                }
            } else {
                println!("[-] Authenticated LDAP bind failed: {} (0x{:X})", rc, rc);
            }
            ldap_unbind(ld2);
        }

        println!("\n[*] Testing LDAPS connectivity (port {})...", LDAPS_PORT);

        let ld3 = ldap_initA(dc_cstr.as_ptr(), LDAPS_PORT);
        if ld3.is_null() {
            println!("[-] LDAPS: ldap_initA failed - LDAPS may not be available.");
        } else {
            let on: u32 = 1;
            let opt_rc = ldap_set_optionA(
                ld3,
                LDAP_OPT_SSL,
                &on as *const u32 as *const core::ffi::c_void,
            );

            if opt_rc != LDAP_SUCCESS {
                println!("[-] LDAPS: Failed to set SSL option: {}", opt_rc);
            }

            let rc = ldap_bind_sA(
                ld3,
                core::ptr::null(),
                core::ptr::null(),
                LDAP_AUTH_NEGOTIATE,
            );
            if rc == LDAP_SUCCESS {
                println!("[+] LDAPS connection succeeded - SSL/TLS is available.");
                println!("    Channel binding can be enforced over LDAPS.");
            } else {
                let err = LdapGetLastError();
                println!(
                    "[-] LDAPS bind failed: {} (0x{:X}), last error: {}",
                    rc, rc, err
                );
                println!("    Channel binding may be required or certificate issues exist.");
            }
            ldap_unbind(ld3);
        }

        println!("\n=== LDAP Security Check Complete ===");

        if !dc_info_ptr.is_null() {
            NetApiBufferFree(dc_info_ptr as *const core::ffi::c_void);
        }
    }
}
