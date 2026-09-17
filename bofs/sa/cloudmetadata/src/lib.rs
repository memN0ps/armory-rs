//! # Cloud Metadata Discovery BOF
//!
//! Performs one bounded request against a fixed link-local metadata endpoint.
//! The provider must be selected explicitly. This command does not request AWS
//! IMDSv2 tokens, managed-identity tokens, service-account tokens, or recursive
//! metadata values.
//!
//! ## MITRE ATT&CK
//! - T1580 - Cloud Infrastructure Discovery
//!
//! ## Arguments
//! - `str`: Provider: `azure`, `aws`, or `gcp`.

#![no_std]

use alloc::{string::String, vec::Vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

type InternetHandle = *mut c_void;

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn WinHttpOpen(
        user_agent: *const u16,
        access_type: u32,
        proxy_name: *const u16,
        proxy_bypass: *const u16,
        flags: u32,
    ) -> InternetHandle;
    fn WinHttpConnect(
        session: InternetHandle,
        server_name: *const u16,
        server_port: u16,
        reserved: u32,
    ) -> InternetHandle;
    fn WinHttpOpenRequest(
        connect: InternetHandle,
        verb: *const u16,
        object_name: *const u16,
        version: *const u16,
        referrer: *const u16,
        accept_types: *const *const u16,
        flags: u32,
    ) -> InternetHandle;
    fn WinHttpAddRequestHeaders(
        request: InternetHandle,
        headers: *const u16,
        headers_length: u32,
        modifiers: u32,
    ) -> i32;
    fn WinHttpSetTimeouts(
        handle: InternetHandle,
        resolve_timeout: i32,
        connect_timeout: i32,
        send_timeout: i32,
        receive_timeout: i32,
    ) -> i32;
    fn WinHttpSendRequest(
        request: InternetHandle,
        headers: *const u16,
        headers_length: u32,
        optional: *mut c_void,
        optional_length: u32,
        total_length: u32,
        context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(request: InternetHandle, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(
        request: InternetHandle,
        info_level: u32,
        name: *const u16,
        buffer: *mut c_void,
        buffer_length: *mut u32,
        index: *mut u32,
    ) -> i32;
    fn WinHttpReadData(
        request: InternetHandle,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
    ) -> i32;
    fn WinHttpCloseHandle(handle: InternetHandle) -> i32;
}

const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x20000000;
const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x20000000;
const HTTP_PORT: u16 = 80;
const TIMEOUT_MS: i32 = 2000;
const RESPONSE_LIMIT: usize = 16 * 1024;

struct PackedArgs<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> PackedArgs<'a> {
    fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < 4 {
            return None;
        }
        let declared = u32::from_le_bytes(buffer[..4].try_into().ok()?) as usize;
        if declared != buffer.len() - 4 {
            return None;
        }
        Some(Self { buffer, offset: 4 })
    }

    fn read_string(&mut self) -> Option<&'a str> {
        let end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..end)?.try_into().ok()?) as usize;
        self.offset = end;
        if length == 0 {
            return None;
        }
        let end = self.offset.checked_add(length)?;
        let value = self.buffer.get(self.offset..end)?;
        self.offset = end;
        if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&value[..length - 1]).ok()
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

struct RequestProfile {
    label: &'static str,
    path: &'static str,
    header: &'static str,
}

fn profile(provider: &str) -> Option<RequestProfile> {
    if provider.eq_ignore_ascii_case("azure") {
        Some(RequestProfile {
            label: "Azure instance name",
            path: "/metadata/instance/compute/name?api-version=2021-02-01&format=text",
            header: "Metadata: true\r\n",
        })
    } else if provider.eq_ignore_ascii_case("aws") {
        Some(RequestProfile {
            label: "AWS metadata categories",
            path: "/latest/meta-data/",
            header: "",
        })
    } else if provider.eq_ignore_ascii_case("gcp") {
        Some(RequestProfile {
            label: "GCP instance metadata categories",
            path: "/computeMetadata/v1/instance/?recursive=false",
            header: "Metadata-Flavor: Google\r\n",
        })
    } else {
        None
    }
}

fn wide_z(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

struct Handles {
    session: InternetHandle,
    connect: InternetHandle,
    request: InternetHandle,
}

impl Handles {
    fn new() -> Self {
        Self {
            session: core::ptr::null_mut(),
            connect: core::ptr::null_mut(),
            request: core::ptr::null_mut(),
        }
    }
}

impl Drop for Handles {
    fn drop(&mut self) {
        unsafe {
            if !self.request.is_null() {
                WinHttpCloseHandle(self.request);
            }
            if !self.connect.is_null() {
                WinHttpCloseHandle(self.connect);
            }
            if !self.session.is_null() {
                WinHttpCloseHandle(self.session);
            }
        }
    }
}

fn request(profile: &RequestProfile) -> Result<(u32, String, bool), (&'static str, u32)> {
    let agent = wide_z("Mozilla/5.0");
    let host = wide_z("169.254.169.254");
    let verb = wide_z("GET");
    let path = wide_z(profile.path);
    let mut handles = Handles::new();

    unsafe {
        handles.session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            core::ptr::null(),
            core::ptr::null(),
            0,
        );
        if handles.session.is_null() {
            return Err(("WinHttpOpen", GetLastError()));
        }
        if WinHttpSetTimeouts(
            handles.session,
            TIMEOUT_MS,
            TIMEOUT_MS,
            TIMEOUT_MS,
            TIMEOUT_MS,
        ) == 0
        {
            return Err(("WinHttpSetTimeouts", GetLastError()));
        }

        handles.connect = WinHttpConnect(handles.session, host.as_ptr(), HTTP_PORT, 0);
        if handles.connect.is_null() {
            return Err(("WinHttpConnect", GetLastError()));
        }
        handles.request = WinHttpOpenRequest(
            handles.connect,
            verb.as_ptr(),
            path.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
        );
        if handles.request.is_null() {
            return Err(("WinHttpOpenRequest", GetLastError()));
        }

        if !profile.header.is_empty() {
            let headers = wide_z(profile.header);
            if WinHttpAddRequestHeaders(
                handles.request,
                headers.as_ptr(),
                u32::MAX,
                WINHTTP_ADDREQ_FLAG_ADD,
            ) == 0
            {
                return Err(("WinHttpAddRequestHeaders", GetLastError()));
            }
        }

        if WinHttpSendRequest(
            handles.request,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            0,
            0,
            0,
        ) == 0
        {
            return Err(("WinHttpSendRequest", GetLastError()));
        }
        if WinHttpReceiveResponse(handles.request, core::ptr::null_mut()) == 0 {
            return Err(("WinHttpReceiveResponse", GetLastError()));
        }

        let mut status = 0u32;
        let mut status_size = core::mem::size_of::<u32>() as u32;
        if WinHttpQueryHeaders(
            handles.request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            core::ptr::null(),
            &mut status as *mut u32 as *mut c_void,
            &mut status_size,
            core::ptr::null_mut(),
        ) == 0
        {
            return Err(("WinHttpQueryHeaders", GetLastError()));
        }

        let mut response = Vec::new();
        let mut chunk = [0u8; 2048];
        let mut truncated = false;
        loop {
            let mut bytes_read = 0u32;
            if WinHttpReadData(
                handles.request,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len() as u32,
                &mut bytes_read,
            ) == 0
            {
                return Err(("WinHttpReadData", GetLastError()));
            }
            if bytes_read == 0 {
                break;
            }

            let remaining = RESPONSE_LIMIT.saturating_sub(response.len());
            if bytes_read as usize > remaining {
                response.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
            response.extend_from_slice(&chunk[..bytes_read as usize]);
            if response.len() == RESPONSE_LIMIT {
                truncated = true;
                break;
            }
        }

        Ok((
            status,
            String::from_utf8_lossy(&response).into_owned(),
            truncated,
        ))
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let provider = parser.read_string()?;
            parser.finished().then_some(provider)
        })
    };

    match parsed {
        None => eprintln!("Usage: cloudmetadata <azure|aws|gcp>"),
        Some(provider_name) => match profile(provider_name) {
            None => eprintln!("Unsupported provider. Use azure, aws, or gcp."),
            Some(profile) => {
                println!("Cloud metadata discovery");
                println!("Provider: {} | request: {}", provider_name, profile.label);
                println!(
                    "Fixed link-local endpoint | timeout: 2000 ms | response cap: 16384 bytes"
                );
                println!("Credential and identity-token endpoints are not requested.\n");

                match request(&profile) {
                    Ok((status, body, truncated)) => {
                        println!("HTTP status: {}", status);
                        if body.is_empty() {
                            println!("<empty response>");
                        } else {
                            println!("{}", body);
                        }
                        if truncated {
                            println!("\nResponse limit reached.");
                        }
                    }
                    Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
                }
            }
        },
    }
}
