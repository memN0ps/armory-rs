//! # Windows Event Log BOF
//!
//! Inspects Windows Event Log channels and manages one exact classic custom
//! log through an ownership-checked create, write, clear, and destroy cycle.
//! Arbitrary channel clearing requires an explicit absolute backup path.
//!
//! ## MITRE ATT&CK
//! - T1070.001 - Indicator Removal: Clear Windows Event Logs
//! - T1562.002 - Impair Defenses: Disable Windows Event Logging
//!
//! ## Arguments
//! - `str`: `inspect`, `sources`, `create`, `write`, `clear`, or `destroy`.
//! - `str`: Channel or classic log name.
//! - Optional `str`: Source name; pass an empty string when clearing.
//! - Optional `str`: Event text or absolute backup path.

#![no_std]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::{eprintln, println};

type Handle = *mut c_void;
type HKey = *mut c_void;
type EvtHandle = *mut c_void;

#[repr(C)]
struct EvtVariant {
    data: u64,
    count: u32,
    value_type: u32,
}

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn RegCreateKeyExW(
        key: HKey,
        subkey: *const u16,
        reserved: u32,
        class: *mut u16,
        options: u32,
        access: u32,
        security: *const c_void,
        result: *mut HKey,
        disposition: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        key: HKey,
        subkey: *const u16,
        options: u32,
        access: u32,
        result: *mut HKey,
    ) -> i32;
    fn RegSetValueExW(
        key: HKey,
        name: *const u16,
        reserved: u32,
        value_type: u32,
        data: *const u8,
        size: u32,
    ) -> i32;
    fn RegQueryValueExW(
        key: HKey,
        name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
    fn RegEnumKeyExW(
        key: HKey,
        index: u32,
        name: *mut u16,
        name_length: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_length: *mut u32,
        last_write: *mut c_void,
    ) -> i32;
    fn RegDeleteTreeW(key: HKey, subkey: *const u16) -> i32;
    fn RegCloseKey(key: HKey) -> i32;
    fn RegisterEventSourceW(server: *const u16, source: *const u16) -> Handle;
    fn ReportEventW(
        event_log: Handle,
        event_type: u16,
        category: u16,
        event_id: u32,
        user_sid: *const c_void,
        string_count: u16,
        data_size: u32,
        strings: *const *const u16,
        raw_data: *const c_void,
    ) -> i32;
    fn DeregisterEventSource(event_log: Handle) -> i32;
    fn EvtOpenChannelConfig(session: EvtHandle, channel: *const u16, flags: u32) -> EvtHandle;
    fn EvtGetChannelConfigProperty(
        config: EvtHandle,
        property_id: u32,
        flags: u32,
        buffer_size: u32,
        buffer: *mut EvtVariant,
        used: *mut u32,
    ) -> i32;
    fn EvtClearLog(session: EvtHandle, channel: *const u16, backup: *const u16, flags: u32) -> i32;
    fn EvtClose(object: EvtHandle) -> i32;
}

const HKEY_LOCAL_MACHINE: HKey = 0x80000002usize as HKey;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_CREATE_SUB_KEY: u32 = 0x0004;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
const KEY_READ: u32 = 0x20019;
const KEY_WRITE: u32 = 0x20006;
const EVENTLOG_INFORMATION_TYPE: u16 = 4;
const EVT_CHANNEL_CONFIG_ENABLED: u32 = 0;
const EVT_CHANNEL_CONFIG_CLASSIC_EVENTLOG: u32 = 4;
const EVT_CHANNEL_CONFIG_RETENTION: u32 = 6;
const EVT_CHANNEL_CONFIG_AUTOBACKUP: u32 = 7;
const EVT_CHANNEL_CONFIG_MAX_SIZE: u32 = 8;
const EVT_CHANNEL_CONFIG_LOG_FILE_PATH: u32 = 9;
const OWNER_NAME: &str = "ArmoryOwner";
const OWNER_VALUE: &str = "armory-eventlog-v1";
const EVENT_LOG_BASE: &str = "SYSTEM\\CurrentControlSet\\Services\\EventLog";
const MAX_SOURCES: u32 = 64;

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

    fn string(&mut self, maximum: usize) -> Option<&'a str> {
        let size_end = self.offset.checked_add(4)?;
        let size =
            u32::from_le_bytes(self.buffer.get(self.offset..size_end)?.try_into().ok()?) as usize;
        self.offset = size_end;
        if size == 0 || size > maximum + 1 {
            return None;
        }
        let value_end = self.offset.checked_add(size)?;
        let value = self.buffer.get(self.offset..value_end)?;
        self.offset = value_end;
        if value.last().copied() != Some(0) || value[..size - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&value[..size - 1]).ok()
    }

    fn remaining(&self) -> bool {
        self.offset < self.buffer.len()
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

struct Key(HKey);

impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn path(log: &str, source: Option<&str>) -> String {
    let mut result = String::from(EVENT_LOG_BASE);
    result.push('\\');
    result.push_str(log);
    if let Some(source) = source {
        result.push('\\');
        result.push_str(source);
    }
    result
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" .-_".contains(&byte))
}

fn protected_name(value: &str) -> bool {
    value.eq_ignore_ascii_case("Application")
        || value.eq_ignore_ascii_case("Security")
        || value.eq_ignore_ascii_case("System")
        || value
            .as_bytes()
            .get(..18)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Microsoft-Windows-"))
}

fn absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        || value.starts_with("\\\\")
}

fn open_key(subkey: &str, access: u32) -> Result<Key, i32> {
    let subkey = wide(subkey);
    let mut key = core::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, access, &mut key) };
    if status == ERROR_SUCCESS {
        Ok(Key(key))
    } else {
        Err(status)
    }
}

fn set_string(key: HKey, name: &str, value: &str) -> Result<(), i32> {
    let name = wide(name);
    let value = wide(value);
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

fn set_dword(key: HKey, name: &str, value: u32) -> Result<(), i32> {
    let name = wide(name);
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_DWORD,
            (&value as *const u32).cast(),
            4,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

fn query_string(key: HKey, name: &str) -> Result<String, i32> {
    let name = wide(name);
    let mut buffer = [0u16; 128];
    let mut size = (buffer.len() * 2) as u32;
    let mut value_type = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS
        || value_type != REG_SZ
        || size < 2
        || size as usize > buffer.len() * 2
    {
        return Err(status);
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn source_exists(log: &str, source: &str) -> Result<(), i32> {
    open_key(&path(log, Some(source)), KEY_QUERY_VALUE).map(|_| ())
}

fn create(log: &str, source: &str) -> Result<(), (&'static str, i32)> {
    if !valid_name(log)
        || !valid_name(source)
        || log.eq_ignore_ascii_case(source)
        || protected_name(log)
    {
        return Err(("name-policy", 87));
    }
    match open_key(&path(log, None), KEY_READ) {
        Ok(_) => return Err(("name-collision", 183)),
        Err(status) if status != ERROR_FILE_NOT_FOUND => return Err(("collision-check", status)),
        Err(_) => {}
    }

    let log_path = wide(&path(log, None));
    let mut log_key = core::ptr::null_mut();
    let mut disposition = 0u32;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            log_path.as_ptr(),
            0,
            core::ptr::null_mut(),
            0,
            KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY,
            core::ptr::null(),
            &mut log_key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(("RegCreateKeyExW(log)", status));
    }
    let log_key = Key(log_key);
    let configured = set_string(log_key.0, OWNER_NAME, OWNER_VALUE)
        .and_then(|_| set_string(log_key.0, "Sources", source))
        .and_then(|_| set_dword(log_key.0, "MaxSize", 1_048_576))
        .and_then(|_| set_dword(log_key.0, "Retention", 0))
        .and_then(|_| set_dword(log_key.0, "AutoBackupLogFiles", 0));
    if let Err(status) = configured {
        drop(log_key);
        unsafe {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, log_path.as_ptr());
        }
        return Err(("configure-log", status));
    }

    let source_name = wide(source);
    let mut source_key = core::ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            log_key.0,
            source_name.as_ptr(),
            0,
            core::ptr::null_mut(),
            0,
            KEY_READ | KEY_WRITE,
            core::ptr::null(),
            &mut source_key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        drop(log_key);
        unsafe {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, log_path.as_ptr());
        }
        return Err(("RegCreateKeyExW(source)", status));
    }
    let source_key = Key(source_key);
    if let Err(status) = set_dword(source_key.0, "TypesSupported", 7) {
        drop(source_key);
        drop(log_key);
        unsafe {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, log_path.as_ptr());
        }
        return Err(("configure-source", status));
    }

    println!(
        "Created classic event log | log={} | source={}",
        log, source
    );
    println!(
        "Ownership marker={} | max-size=1048576 | retention=overwrite",
        OWNER_VALUE
    );
    Ok(())
}

fn sources(log: &str) -> Result<(), (&'static str, i32)> {
    let key = open_key(&path(log, None), KEY_ENUMERATE_SUB_KEYS)
        .map_err(|status| ("open-log", status))?;
    let mut shown = 0u32;
    for index in 0..MAX_SOURCES {
        let mut name = [0u16; 260];
        let mut length = (name.len() - 1) as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            return Err(("RegEnumKeyExW", status));
        }
        println!(
            "source[{}]={}",
            shown,
            String::from_utf16_lossy(&name[..length as usize])
        );
        shown += 1;
    }
    println!(
        "Sources shown: {}{}",
        shown,
        if shown == MAX_SOURCES {
            " | limit reached"
        } else {
            ""
        }
    );
    Ok(())
}

fn write(log: &str, source: &str, text: &str) -> Result<(), (&'static str, i32)> {
    if text.is_empty() || text.len() > 12_288 || log.eq_ignore_ascii_case("Security") {
        return Err(("write-policy", 87));
    }
    source_exists(log, source).map_err(|status| ("source-validation", status))?;
    let source_wide = wide(source);
    let text_wide = wide(text);
    let handle = unsafe { RegisterEventSourceW(core::ptr::null(), source_wide.as_ptr()) };
    if handle.is_null() {
        return Err(("RegisterEventSourceW", (unsafe { GetLastError() }) as i32));
    }
    let strings = [text_wide.as_ptr()];
    let success = unsafe {
        ReportEventW(
            handle,
            EVENTLOG_INFORMATION_TYPE,
            0,
            1,
            core::ptr::null(),
            1,
            0,
            strings.as_ptr(),
            core::ptr::null(),
        )
    };
    let status = if success == 0 {
        (unsafe { GetLastError() }) as i32
    } else {
        ERROR_SUCCESS
    };
    unsafe {
        DeregisterEventSource(handle);
    }
    if status == ERROR_SUCCESS {
        println!(
            "Wrote classic event | log={} | source={} | utf8-bytes={}",
            log,
            source,
            text.len()
        );
        Ok(())
    } else {
        Err(("ReportEventW", status))
    }
}

fn property(config: EvtHandle, property_id: u32) -> Option<Vec<u64>> {
    let mut buffer = vec![0u64; 2048];
    let mut used = 0u32;
    let success = unsafe {
        EvtGetChannelConfigProperty(
            config,
            property_id,
            0,
            (buffer.len() * 8) as u32,
            buffer.as_mut_ptr().cast(),
            &mut used,
        )
    };
    if success == 0
        || used < core::mem::size_of::<EvtVariant>() as u32
        || used as usize > buffer.len() * 8
    {
        None
    } else {
        Some(buffer)
    }
}

fn numeric_property(config: EvtHandle, property_id: u32) -> Option<u64> {
    let buffer = property(config, property_id)?;
    Some(unsafe { (*(buffer.as_ptr() as *const EvtVariant)).data })
}

fn string_property(config: EvtHandle, property_id: u32) -> Option<String> {
    let buffer = property(config, property_id)?;
    let variant = unsafe { &*(buffer.as_ptr() as *const EvtVariant) };
    let pointer = variant.data as *const u16;
    if pointer.is_null() {
        return None;
    }
    let mut length = 0usize;
    while length < 4096 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 4096 {
        None
    } else {
        Some(String::from_utf16_lossy(unsafe {
            core::slice::from_raw_parts(pointer, length)
        }))
    }
}

fn inspect(channel: &str) -> Result<(), (&'static str, i32)> {
    let channel_wide = wide(channel);
    let config = unsafe { EvtOpenChannelConfig(core::ptr::null_mut(), channel_wide.as_ptr(), 0) };
    if config.is_null() {
        return Err(("EvtOpenChannelConfig", (unsafe { GetLastError() }) as i32));
    }
    println!("Event channel: {}", channel);
    println!(
        "enabled={} | classic={} | retention={} | auto-backup={}",
        numeric_property(config, EVT_CHANNEL_CONFIG_ENABLED).unwrap_or(u64::MAX),
        numeric_property(config, EVT_CHANNEL_CONFIG_CLASSIC_EVENTLOG).unwrap_or(u64::MAX),
        numeric_property(config, EVT_CHANNEL_CONFIG_RETENTION).unwrap_or(u64::MAX),
        numeric_property(config, EVT_CHANNEL_CONFIG_AUTOBACKUP).unwrap_or(u64::MAX)
    );
    println!(
        "max-size={} | file={}",
        numeric_property(config, EVT_CHANNEL_CONFIG_MAX_SIZE).unwrap_or(0),
        string_property(config, EVT_CHANNEL_CONFIG_LOG_FILE_PATH)
            .unwrap_or_else(|| String::from("<unavailable>"))
    );
    unsafe {
        EvtClose(config);
    }
    Ok(())
}

fn clear(channel: &str, backup: &str, owned: bool) -> Result<(), (&'static str, i32)> {
    if !owned && (!absolute_path(backup) || backup.len() > 512) {
        return Err(("backup-path-policy", 87));
    }
    let channel_wide = wide(channel);
    let backup_wide = wide(backup);
    let backup_pointer = if backup.is_empty() {
        core::ptr::null()
    } else {
        backup_wide.as_ptr()
    };
    if unsafe {
        EvtClearLog(
            core::ptr::null_mut(),
            channel_wide.as_ptr(),
            backup_pointer,
            0,
        )
    } == 0
    {
        Err(("EvtClearLog", (unsafe { GetLastError() }) as i32))
    } else {
        println!(
            "Cleared event channel | channel={} | backup={}",
            channel,
            if backup.is_empty() { "<none>" } else { backup }
        );
        println!("Event-log clearing is auditable and may already be forwarded off-host");
        Ok(())
    }
}

fn owned(log: &str, source: &str) -> Result<(), (&'static str, i32)> {
    if !valid_name(log) || !valid_name(source) || protected_name(log) {
        return Err(("name-policy", 87));
    }
    let key = open_key(&path(log, None), KEY_QUERY_VALUE).map_err(|status| ("open-log", status))?;
    let marker = query_string(key.0, OWNER_NAME).map_err(|status| ("ownership-marker", status))?;
    if marker != OWNER_VALUE {
        return Err(("ownership-mismatch", 5));
    }
    source_exists(log, source).map_err(|status| ("source-validation", status))
}

fn destroy(log: &str, source: &str) -> Result<(), (&'static str, i32)> {
    owned(log, source)?;
    clear(log, "", true)?;
    let log_path = wide(&path(log, None));
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, log_path.as_ptr()) };
    if status == ERROR_SUCCESS {
        println!(
            "Removed owned event-log registration | log={} | source={}",
            log, source
        );
        Ok(())
    } else {
        Err(("RegDeleteTreeW", status))
    }
}

fn parse(args: *mut u8, len: usize) -> Option<(String, String, String, String)> {
    if args.is_null() || len == 0 {
        return None;
    }
    let buffer = unsafe { core::slice::from_raw_parts(args, len) };
    let mut parser = PackedArgs::new(buffer)?;
    let action = String::from(parser.string(16)?);
    let target = String::from(parser.string(512)?);
    let source = if parser.remaining() {
        String::from(parser.string(128)?)
    } else {
        String::new()
    };
    let detail = if parser.remaining() {
        String::from(parser.string(12_288)?)
    } else {
        String::new()
    };
    parser
        .finished()
        .then_some((action, target, source, detail))
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let result = match parse(args, len) {
        None => {
            eprintln!(
                "Usage: eventlog <inspect|sources|create|write|clear|destroy> <channel-or-log> [source] [text-or-backup]"
            );
            None
        }
        Some((action, target, _, _)) if action.eq_ignore_ascii_case("inspect") => {
            Some(inspect(&target))
        }
        Some((action, target, _, _)) if action.eq_ignore_ascii_case("sources") => {
            Some(sources(&target))
        }
        Some((action, target, source, _)) if action.eq_ignore_ascii_case("create") => {
            Some(create(&target, &source))
        }
        Some((action, target, source, detail)) if action.eq_ignore_ascii_case("write") => {
            Some(write(&target, &source, &detail))
        }
        Some((action, target, _, detail)) if action.eq_ignore_ascii_case("clear") => {
            Some(clear(&target, &detail, false))
        }
        Some((action, target, source, _)) if action.eq_ignore_ascii_case("destroy") => {
            Some(destroy(&target, &source))
        }
        Some(_) => Some(Err(("unknown-action", 87))),
    };

    if let Some(Err((stage, status))) = result {
        eprintln!(
            "Event log action failed | stage={} | error={}",
            stage, status
        );
    }
}
