//! # Azure AD Join Info BOF
//!
//! Retrieves Azure AD / Entra ID join information for the local device
//! using NetGetAadJoinInformation. Dynamically loads the function from
//! netapi32.dll via LoadLibraryA/GetProcAddress to avoid linker issues
//! with mingw.
//!
//! ## MITRE ATT&CK
//! - T1087.004 - Account Discovery: Cloud Account
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::string::String;
use rustbof::{eprintln, println};
#[repr(C)]
struct DsregJoinInfo {
    join_type: u32,
    device_id: *mut u16,
    idp_domain: *mut u16,
    tenant_id: *mut u16,
    email: *mut u16,
    display_name: *mut u16,
    mdm_enrollment_url: *mut u16,
    mdm_terms_of_use_url: *mut u16,
    mdm_compliance_url: *mut u16,
    user_setting_sync_url: *mut u16,
    cert_info: *mut core::ffi::c_void,
    user_key_id: *mut u16,
    user_key_name: *mut u16,
}
unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut core::ffi::c_void;
    fn GetProcAddress(module: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void;
    fn FreeLibrary(module: *mut core::ffi::c_void) -> i32;
}

type FnNetGetAadJoinInformation =
    unsafe extern "system" fn(*const u16, *mut *mut DsregJoinInfo) -> i32;
type FnNetFreeAadJoinInformation = unsafe extern "system" fn(*mut DsregJoinInfo);
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

fn join_type_str(t: u32) -> &'static str {
    match t {
        0 => "Not Joined",
        1 => "Azure AD Joined",
        2 => "Azure AD Registered",
        3 => "Hybrid Azure AD Joined",
        _ => "Unknown",
    }
}
#[rustbof::main]
fn main() {
    unsafe {
        let netapi = LoadLibraryA(b"netapi32.dll\0".as_ptr());
        if netapi.is_null() {
            eprintln!("Failed to load netapi32.dll");
            return;
        }

        let get_join_info_ptr = GetProcAddress(netapi, b"NetGetAadJoinInformation\0".as_ptr());
        if get_join_info_ptr.is_null() {
            eprintln!(
                "Failed to resolve NetGetAadJoinInformation - function not available on this OS."
            );
            FreeLibrary(netapi);
            return;
        }

        let free_join_info_ptr = GetProcAddress(netapi, b"NetFreeAadJoinInformation\0".as_ptr());
        if free_join_info_ptr.is_null() {
            eprintln!("Failed to resolve NetFreeAadJoinInformation.");
            FreeLibrary(netapi);
            return;
        }

        let net_get_aad_join_info: FnNetGetAadJoinInformation =
            core::mem::transmute(get_join_info_ptr);
        let net_free_aad_join_info: FnNetFreeAadJoinInformation =
            core::mem::transmute(free_join_info_ptr);

        let mut info: *mut DsregJoinInfo = core::ptr::null_mut();
        let status = net_get_aad_join_info(core::ptr::null(), &mut info);

        if status != 0 {
            eprintln!("NetGetAadJoinInformation failed: {}", status);
            FreeLibrary(netapi);
            return;
        }

        if info.is_null() {
            println!("No Azure AD join information available.");
            FreeLibrary(netapi);
            return;
        }

        let i = &*info;
        println!("Azure AD Join Information:");
        println!("  Join Type:        {}", join_type_str(i.join_type));
        println!("  Device ID:        {}", wide_ptr_to_string(i.device_id));
        println!("  IDP Domain:       {}", wide_ptr_to_string(i.idp_domain));
        println!("  Tenant ID:        {}", wide_ptr_to_string(i.tenant_id));
        println!("  Email:            {}", wide_ptr_to_string(i.email));
        println!("  Display Name:     {}", wide_ptr_to_string(i.display_name));
        println!(
            "  MDM Enroll URL:   {}",
            wide_ptr_to_string(i.mdm_enrollment_url)
        );

        net_free_aad_join_info(info);
        FreeLibrary(netapi);
    }
}
