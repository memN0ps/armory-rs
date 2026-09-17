//! # ADCS Enumeration BOF
//!
//! Enumerates Active Directory Certificate Services (AD CS) Certificate
//! Authorities and certificate templates by dynamically loading certcli.dll
//! and calling the CA enumeration APIs (CAEnumFirstCA, CAEnumCertTypesForCA,
//! etc.).
//!
//! ## MITRE ATT&CK
//! - T1649 - Steal or Forge Authentication Certificates
//!
//! ## Arguments
//! - `scope` (optional, wide string) - Domain/forest scope for CA enumeration.
//!   If empty or omitted, uses the default domain.

#![no_std]

use alloc::string::String;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut core::ffi::c_void;
    fn GetProcAddress(module: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void;
    fn FreeLibrary(module: *mut core::ffi::c_void) -> i32;
}
type CAEnumFirstCA = unsafe extern "system" fn(
    scope: *const u16,
    flags: u32,
    ca_info: *mut *mut core::ffi::c_void,
) -> i32;
type CAEnumNextCA = unsafe extern "system" fn(
    prev: *mut core::ffi::c_void,
    ca_info: *mut *mut core::ffi::c_void,
) -> i32;
type CACloseCA = unsafe extern "system" fn(ca: *mut core::ffi::c_void) -> i32;
type CACountCAs = unsafe extern "system" fn(ca_info: *mut core::ffi::c_void) -> u32;
type CAGetCAProperty = unsafe extern "system" fn(
    ca: *mut core::ffi::c_void,
    prop: *const u16,
    val: *mut *mut *mut u16,
) -> i32;
type CAFreeCAProperty =
    unsafe extern "system" fn(ca: *mut core::ffi::c_void, val: *mut *mut u16) -> i32;

type CAEnumCertTypesForCA = unsafe extern "system" fn(
    ca: *mut core::ffi::c_void,
    flags: u32,
    cert_type: *mut *mut core::ffi::c_void,
) -> i32;
type CAEnumNextCertType = unsafe extern "system" fn(
    prev: *mut core::ffi::c_void,
    cert_type: *mut *mut core::ffi::c_void,
) -> i32;
type CACloseCertType = unsafe extern "system" fn(ct: *mut core::ffi::c_void) -> i32;
type CACountCertTypes = unsafe extern "system" fn(ct: *mut core::ffi::c_void) -> u32;

type CAGetCertTypeProperty = unsafe extern "system" fn(
    ct: *mut core::ffi::c_void,
    prop: *const u16,
    val: *mut *mut *mut u16,
) -> i32;
type CAFreeCertTypeProperty =
    unsafe extern "system" fn(ct: *mut core::ffi::c_void, val: *mut *mut u16) -> i32;
type CAGetCertTypeFlagsEx =
    unsafe extern "system" fn(ct: *mut core::ffi::c_void, option: u32, flags: *mut u32) -> i32;
const CERTTYPE_ENROLLMENT_FLAG: u32 = 0x04;
const CERTTYPE_GENERAL_FLAG: u32 = 0x08;
const CERTTYPE_PRIVATE_KEY_FLAG: u32 = 0x0C;
struct CertCliApi {
    ca_enum_first_ca: CAEnumFirstCA,
    ca_enum_next_ca: CAEnumNextCA,
    ca_close_ca: CACloseCA,
    ca_count_cas: CACountCAs,
    ca_get_ca_property: CAGetCAProperty,
    ca_free_ca_property: CAFreeCAProperty,
    ca_enum_cert_types_for_ca: CAEnumCertTypesForCA,
    ca_enum_next_cert_type: CAEnumNextCertType,
    ca_close_cert_type: CACloseCertType,
    ca_count_cert_types: CACountCertTypes,
    ca_get_cert_type_property: CAGetCertTypeProperty,
    ca_free_cert_type_property: CAFreeCertTypeProperty,
    ca_get_cert_type_flags_ex: CAGetCertTypeFlagsEx,
}
fn read_first_multistring(val: *mut *mut u16) -> String {
    if val.is_null() {
        return String::from("(null)");
    }
    unsafe {
        let first = *val;
        if first.is_null() {
            return String::from("(null)");
        }
        wide_ptr_to_string(first)
    }
}

fn wide_ptr_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::from("(null)");
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

unsafe fn resolve(module: *mut core::ffi::c_void, name: &[u8]) -> Option<*mut core::ffi::c_void> {
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };
    if ptr.is_null() { None } else { Some(ptr) }
}

unsafe fn load_certcli_api(module: *mut core::ffi::c_void) -> Option<CertCliApi> {
    unsafe {
        Some(CertCliApi {
            ca_enum_first_ca: core::mem::transmute(resolve(module, b"CAEnumFirstCA\0")?),
            ca_enum_next_ca: core::mem::transmute(resolve(module, b"CAEnumNextCA\0")?),
            ca_close_ca: core::mem::transmute(resolve(module, b"CACloseCA\0")?),
            ca_count_cas: core::mem::transmute(resolve(module, b"CACountCAs\0")?),
            ca_get_ca_property: core::mem::transmute(resolve(module, b"CAGetCAProperty\0")?),
            ca_free_ca_property: core::mem::transmute(resolve(module, b"CAFreeCAProperty\0")?),
            ca_enum_cert_types_for_ca: core::mem::transmute(resolve(
                module,
                b"CAEnumCertTypesForCA\0",
            )?),
            ca_enum_next_cert_type: core::mem::transmute(resolve(module, b"CAEnumNextCertType\0")?),
            ca_close_cert_type: core::mem::transmute(resolve(module, b"CACloseCertType\0")?),
            ca_count_cert_types: core::mem::transmute(resolve(module, b"CACountCertTypes\0")?),
            ca_get_cert_type_property: core::mem::transmute(resolve(
                module,
                b"CAGetCertTypeProperty\0",
            )?),
            ca_free_cert_type_property: core::mem::transmute(resolve(
                module,
                b"CAFreeCertTypeProperty\0",
            )?),
            ca_get_cert_type_flags_ex: core::mem::transmute(resolve(
                module,
                b"CAGetCertTypeFlagsEx\0",
            )?),
        })
    }
}
unsafe fn enumerate_cert_templates(api: &CertCliApi, ca: *mut core::ffi::c_void) {
    unsafe {
        let mut ct_info: *mut core::ffi::c_void = core::ptr::null_mut();

        let hr = (api.ca_enum_cert_types_for_ca)(ca, 0, &mut ct_info);
        if hr != 0 {
            eprintln!("    CAEnumCertTypesForCA failed: 0x{:08X}", hr as u32);
            return;
        }

        if ct_info.is_null() {
            println!("    No certificate templates found.");
            return;
        }

        let ct_count = (api.ca_count_cert_types)(ct_info);
        println!("    Certificate Templates: {}", ct_count);
        println!();

        let prop_cn = to_wide("cn");
        let prop_dn = to_wide("distinguishedName");
        let prop_display = to_wide("displayName");
        let prop_schema_ver = to_wide("msPKI-Template-Schema-Version");

        let mut current_ct = ct_info;
        let mut idx: u32 = 0;

        while !current_ct.is_null() {
            idx += 1;

            let mut cn_val: *mut *mut u16 = core::ptr::null_mut();
            let cn_name = if (api.ca_get_cert_type_property)(
                current_ct,
                prop_cn.as_ptr(),
                &mut cn_val,
            ) == 0
            {
                let s = read_first_multistring(cn_val);
                (api.ca_free_cert_type_property)(current_ct, cn_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut disp_val: *mut *mut u16 = core::ptr::null_mut();
            let display_name = if (api.ca_get_cert_type_property)(
                current_ct,
                prop_display.as_ptr(),
                &mut disp_val,
            ) == 0
            {
                let s = read_first_multistring(disp_val);
                (api.ca_free_cert_type_property)(current_ct, disp_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut dn_val: *mut *mut u16 = core::ptr::null_mut();
            let dn_name = if (api.ca_get_cert_type_property)(
                current_ct,
                prop_dn.as_ptr(),
                &mut dn_val,
            ) == 0
            {
                let s = read_first_multistring(dn_val);
                (api.ca_free_cert_type_property)(current_ct, dn_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut sv_val: *mut *mut u16 = core::ptr::null_mut();
            let schema_ver = if (api.ca_get_cert_type_property)(
                current_ct,
                prop_schema_ver.as_ptr(),
                &mut sv_val,
            ) == 0
            {
                let s = read_first_multistring(sv_val);
                (api.ca_free_cert_type_property)(current_ct, sv_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut enrollment_flags: u32 = 0;
            let mut general_flags: u32 = 0;
            let mut private_key_flags: u32 = 0;
            let _ = (api.ca_get_cert_type_flags_ex)(
                current_ct,
                CERTTYPE_ENROLLMENT_FLAG,
                &mut enrollment_flags,
            );
            let _ = (api.ca_get_cert_type_flags_ex)(
                current_ct,
                CERTTYPE_GENERAL_FLAG,
                &mut general_flags,
            );
            let _ = (api.ca_get_cert_type_flags_ex)(
                current_ct,
                CERTTYPE_PRIVATE_KEY_FLAG,
                &mut private_key_flags,
            );

            println!("    [{}] Template: {}", idx, cn_name);
            println!("        Display Name:      {}", display_name);
            println!("        DN:                {}", dn_name);
            println!("        Schema Version:    {}", schema_ver);
            println!("        Enrollment Flags:  0x{:08X}", enrollment_flags);
            println!("        General Flags:     0x{:08X}", general_flags);
            println!("        Private Key Flags: 0x{:08X}", private_key_flags);
            println!();

            let mut next_ct: *mut core::ffi::c_void = core::ptr::null_mut();
            let hr = (api.ca_enum_next_cert_type)(current_ct, &mut next_ct);
            if hr != 0 || next_ct.is_null() {
                break;
            }
            current_ct = next_ct;
        }

        (api.ca_close_cert_type)(ct_info);
    }
}
#[rustbof::main]
fn main() {
    println!("=== ADCS Enumeration (T1649) ===");
    println!();

    unsafe {
        let certcli = LoadLibraryA(b"certcli.dll\0".as_ptr());
        if certcli.is_null() {
            eprintln!("Failed to load certcli.dll - ADCS role may not be installed.");
            return;
        }

        let api = match load_certcli_api(certcli) {
            Some(a) => a,
            None => {
                eprintln!("Failed to resolve one or more certcli.dll exports.");
                FreeLibrary(certcli);
                return;
            }
        };

        let scope_ptr: *const u16 = core::ptr::null();

        let mut ca_info: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr = (api.ca_enum_first_ca)(scope_ptr, 0, &mut ca_info);
        if hr != 0 {
            eprintln!("CAEnumFirstCA failed: 0x{:08X}", hr as u32);
            FreeLibrary(certcli);
            return;
        }

        if ca_info.is_null() {
            println!("No Certificate Authorities found in the domain.");
            FreeLibrary(certcli);
            return;
        }

        let ca_count = (api.ca_count_cas)(ca_info);
        println!(
            "Found {} Certificate Authorit{}",
            ca_count,
            if ca_count == 1 { "y" } else { "ies" }
        );
        println!();

        let prop_cn = to_wide("cn");
        let prop_dn = to_wide("distinguishedName");
        let prop_dns = to_wide("dNSHostName");

        let mut current_ca = ca_info;
        let mut ca_idx: u32 = 0;

        while !current_ca.is_null() {
            ca_idx += 1;

            let mut cn_val: *mut *mut u16 = core::ptr::null_mut();
            let ca_cn = if (api.ca_get_ca_property)(current_ca, prop_cn.as_ptr(), &mut cn_val) == 0
            {
                let s = read_first_multistring(cn_val);
                (api.ca_free_ca_property)(current_ca, cn_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut dn_val: *mut *mut u16 = core::ptr::null_mut();
            let ca_dn = if (api.ca_get_ca_property)(current_ca, prop_dn.as_ptr(), &mut dn_val) == 0
            {
                let s = read_first_multistring(dn_val);
                (api.ca_free_ca_property)(current_ca, dn_val);
                s
            } else {
                String::from("(unknown)")
            };

            let mut dns_val: *mut *mut u16 = core::ptr::null_mut();
            let ca_dns =
                if (api.ca_get_ca_property)(current_ca, prop_dns.as_ptr(), &mut dns_val) == 0 {
                    let s = read_first_multistring(dns_val);
                    (api.ca_free_ca_property)(current_ca, dns_val);
                    s
                } else {
                    String::from("(unknown)")
                };

            println!("[CA {}] {}", ca_idx, ca_cn);
            println!("  DN:        {}", ca_dn);
            println!("  DNS Host:  {}", ca_dns);
            println!();

            enumerate_cert_templates(&api, current_ca);

            let mut next_ca: *mut core::ffi::c_void = core::ptr::null_mut();
            let hr = (api.ca_enum_next_ca)(current_ca, &mut next_ca);
            if hr != 0 || next_ca.is_null() {
                break;
            }
            current_ca = next_ca;
        }

        (api.ca_close_ca)(ca_info);
        FreeLibrary(certcli);
    }

    println!("=== ADCS enumeration complete ===");
}
