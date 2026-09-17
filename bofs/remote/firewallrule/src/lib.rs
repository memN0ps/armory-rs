//! # Windows Firewall Rule BOF
//!
//! Queries, adds, or removes one exact named Windows Firewall rule through
//! INetFwPolicy2. Add refuses a name collision. Remove is the explicit rollback
//! action and should be used only with the exact unique name returned by add.
//!
//! ## MITRE ATT&CK
//! - T1562.004 - Impair Defenses: Disable or Modify System Firewall
//!
//! ## Arguments
//! Seven packed strings: action, name, direction, decision, protocol, local
//! ports, and application. For query/remove, pass empty strings after name.

#![no_std]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::{eprintln, println};

type HResult = i32;
type BstrRaw = *mut u16;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency: u32) -> HResult;
    fn CoCreateInstance(
        class_id: *const Guid,
        outer: *mut c_void,
        context: u32,
        interface_id: *const Guid,
        object: *mut *mut c_void,
    ) -> HResult;
    fn CoUninitialize();
    fn SysAllocStringLen(source: *const u16, length: u32) -> BstrRaw;
    fn SysFreeString(value: BstrRaw);
    fn SysStringLen(value: BstrRaw) -> u32;
}

const S_OK: HResult = 0;
const S_FALSE: HResult = 1;
const RPC_E_CHANGED_MODE: HResult = 0x80010106u32 as i32;
const HRESULT_FILE_NOT_FOUND: HResult = 0x80070002u32 as i32;
const COINIT_MULTITHREADED: u32 = 0;
const CLSCTX_INPROC_SERVER: u32 = 1;
const VARIANT_TRUE: i16 = -1;
const NET_FW_PROFILE2_ALL: i32 = 0x7FFFFFFF;

const CLSID_NET_FW_POLICY2: Guid = Guid {
    data1: 0xE2B3C97F,
    data2: 0x6AE1,
    data3: 0x41AC,
    data4: [0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD],
};
const IID_INET_FW_POLICY2: Guid = Guid {
    data1: 0x98325047,
    data2: 0xC671,
    data3: 0x4174,
    data4: [0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86],
};
const CLSID_NET_FW_RULE: Guid = Guid {
    data1: 0x2C5BC43E,
    data2: 0x3369,
    data3: 0x4C33,
    data4: [0xAB, 0x0C, 0xBE, 0x94, 0x69, 0x67, 0x7A, 0xF4],
};
const IID_INET_FW_RULE: Guid = Guid {
    data1: 0xAF230D27,
    data2: 0xBABA,
    data3: 0x4E42,
    data4: [0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2],
};

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

    fn read_string(&mut self, maximum: usize, allow_empty: bool) -> Option<&'a str> {
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
        let value = core::str::from_utf8(&value[..size - 1]).ok()?;
        if !allow_empty && value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

struct Bstr(BstrRaw);

impl Bstr {
    fn new(value: &str) -> Result<Self, (&'static str, HResult)> {
        let length = value.encode_utf16().count();
        let pointer = unsafe { SysAllocStringLen(core::ptr::null(), length as u32) };
        if pointer.is_null() {
            Err(("SysAllocStringLen", 0x8007000Eu32 as i32))
        } else {
            for (index, character) in value.encode_utf16().enumerate() {
                unsafe {
                    *pointer.add(index) = character;
                }
            }
            Ok(Self(pointer))
        }
    }

    fn as_raw(&self) -> BstrRaw {
        self.0
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { SysFreeString(self.0) };
        }
    }
}

fn take_bstr(pointer: BstrRaw) -> String {
    if pointer.is_null() {
        return String::new();
    }
    unsafe {
        let length = core::cmp::min(SysStringLen(pointer) as usize, 32768);
        let value = String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length));
        SysFreeString(pointer);
        value
    }
}

unsafe fn vtable_entry(object: *mut c_void, index: usize) -> *const c_void {
    unsafe { *(*(object as *mut *mut *mut c_void)).add(index) as *const c_void }
}

unsafe fn release(object: *mut c_void) {
    if !object.is_null() {
        type Release = unsafe extern "system" fn(*mut c_void) -> u32;
        let function: Release = unsafe { core::mem::transmute(vtable_entry(object, 2)) };
        unsafe { function(object) };
    }
}

struct Firewall {
    policy: *mut c_void,
    rules: *mut c_void,
    uninitialize: bool,
}

impl Firewall {
    fn open() -> Result<Self, (&'static str, HResult)> {
        unsafe {
            let initialize = CoInitializeEx(core::ptr::null_mut(), COINIT_MULTITHREADED);
            let uninitialize = initialize == S_OK || initialize == S_FALSE;
            if initialize < 0 && initialize != RPC_E_CHANGED_MODE {
                return Err(("CoInitializeEx", initialize));
            }

            let mut policy = core::ptr::null_mut();
            let create = CoCreateInstance(
                &CLSID_NET_FW_POLICY2,
                core::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_INET_FW_POLICY2,
                &mut policy,
            );
            if create < 0 || policy.is_null() {
                if uninitialize {
                    CoUninitialize();
                }
                return Err(("CoCreateInstance(INetFwPolicy2)", create));
            }

            type GetRules = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HResult;
            let get_rules: GetRules = core::mem::transmute(vtable_entry(policy, 18));
            let mut rules = core::ptr::null_mut();
            let result = get_rules(policy, &mut rules);
            if result < 0 || rules.is_null() {
                release(policy);
                if uninitialize {
                    CoUninitialize();
                }
                return Err(("INetFwPolicy2::get_Rules", result));
            }
            Ok(Self {
                policy,
                rules,
                uninitialize,
            })
        }
    }

    fn item(&self, name: &Bstr) -> Result<Option<*mut c_void>, HResult> {
        unsafe {
            type Item =
                unsafe extern "system" fn(*mut c_void, BstrRaw, *mut *mut c_void) -> HResult;
            let item: Item = core::mem::transmute(vtable_entry(self.rules, 10));
            let mut rule = core::ptr::null_mut();
            let result = item(self.rules, name.as_raw(), &mut rule);
            if result == HRESULT_FILE_NOT_FOUND {
                if !rule.is_null() {
                    release(rule);
                }
                Ok(None)
            } else if result < 0 {
                if !rule.is_null() {
                    release(rule);
                }
                Err(result)
            } else if rule.is_null() {
                Err(0x80004005u32 as i32)
            } else {
                Ok(Some(rule))
            }
        }
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        unsafe {
            release(self.rules);
            release(self.policy);
            if self.uninitialize {
                CoUninitialize();
            }
        }
    }
}

fn put_i32(rule: *mut c_void, index: usize, value: i32) -> HResult {
    unsafe {
        type Put = unsafe extern "system" fn(*mut c_void, i32) -> HResult;
        let put: Put = core::mem::transmute(vtable_entry(rule, index));
        put(rule, value)
    }
}

fn put_i16(rule: *mut c_void, index: usize, value: i16) -> HResult {
    unsafe {
        type Put = unsafe extern "system" fn(*mut c_void, i16) -> HResult;
        let put: Put = core::mem::transmute(vtable_entry(rule, index));
        put(rule, value)
    }
}

fn put_bstr(rule: *mut c_void, index: usize, value: &Bstr) -> HResult {
    unsafe {
        type Put = unsafe extern "system" fn(*mut c_void, BstrRaw) -> HResult;
        let put: Put = core::mem::transmute(vtable_entry(rule, index));
        put(rule, value.as_raw())
    }
}

fn get_i32(
    rule: *mut c_void,
    index: usize,
    stage: &'static str,
) -> Result<i32, (&'static str, HResult)> {
    unsafe {
        type Get = unsafe extern "system" fn(*mut c_void, *mut i32) -> HResult;
        let get: Get = core::mem::transmute(vtable_entry(rule, index));
        let mut value = 0i32;
        let result = get(rule, &mut value);
        if result < 0 {
            Err((stage, result))
        } else {
            Ok(value)
        }
    }
}

fn get_i16(
    rule: *mut c_void,
    index: usize,
    stage: &'static str,
) -> Result<i16, (&'static str, HResult)> {
    unsafe {
        type Get = unsafe extern "system" fn(*mut c_void, *mut i16) -> HResult;
        let get: Get = core::mem::transmute(vtable_entry(rule, index));
        let mut value = 0i16;
        let result = get(rule, &mut value);
        if result < 0 {
            Err((stage, result))
        } else {
            Ok(value)
        }
    }
}

fn get_bstr(
    rule: *mut c_void,
    index: usize,
    stage: &'static str,
) -> Result<String, (&'static str, HResult)> {
    unsafe {
        type Get = unsafe extern "system" fn(*mut c_void, *mut BstrRaw) -> HResult;
        let get: Get = core::mem::transmute(vtable_entry(rule, index));
        let mut value = core::ptr::null_mut();
        let result = get(rule, &mut value);
        if result < 0 {
            if !value.is_null() {
                SysFreeString(value);
            }
            Err((stage, result))
        } else {
            Ok(take_bstr(value))
        }
    }
}

fn query(firewall: &Firewall, name: &Bstr) -> Result<bool, (&'static str, HResult)> {
    match firewall.item(name) {
        Ok(None) => Ok(false),
        Err(status) => Err(("INetFwRules::Item", status)),
        Ok(Some(rule)) => {
            let result = (|| {
                let direction = get_i32(rule, 27, "INetFwRule::get_Direction")?;
                let protocol = get_i32(rule, 15, "INetFwRule::get_Protocol")?;
                let enabled = get_i16(rule, 33, "INetFwRule::get_Enabled")?;
                let action = get_i32(rule, 41, "INetFwRule::get_Action")?;
                let ports = get_bstr(rule, 17, "INetFwRule::get_LocalPorts")?;
                let program = get_bstr(rule, 11, "INetFwRule::get_ApplicationName")?;
                println!(
                    "Rule exists | direction={} | action={} | protocol={} | enabled={} | ports={} | application={}",
                    if direction == 1 { "in" } else { "out" },
                    if action == 1 { "allow" } else { "block" },
                    protocol,
                    if enabled != 0 { "yes" } else { "no" },
                    ports,
                    program
                );
                Ok(true)
            })();
            unsafe {
                release(rule);
            }
            result
        }
    }
}

fn add(
    firewall: &Firewall,
    name: &Bstr,
    direction: i32,
    action: i32,
    protocol: i32,
    ports: &str,
    application: &str,
) -> Result<(), (&'static str, HResult)> {
    if let Some(existing) = firewall
        .item(name)
        .map_err(|status| ("INetFwRules::Item", status))?
    {
        unsafe {
            release(existing);
        }
        return Err(("rule already exists; refusing overwrite", 0));
    }

    unsafe {
        let mut rule = core::ptr::null_mut();
        let create = CoCreateInstance(
            &CLSID_NET_FW_RULE,
            core::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_INET_FW_RULE,
            &mut rule,
        );
        if create < 0 || rule.is_null() {
            return Err(("CoCreateInstance(INetFwRule)", create));
        }

        let result = (|| {
            let name_result = put_bstr(rule, 8, name);
            if name_result < 0 {
                return Err(("INetFwRule::put_Name", name_result));
            }
            for (stage, result) in [
                ("INetFwRule::put_Direction", put_i32(rule, 28, direction)),
                ("INetFwRule::put_Action", put_i32(rule, 42, action)),
                ("INetFwRule::put_Protocol", put_i32(rule, 16, protocol)),
                (
                    "INetFwRule::put_Profiles",
                    put_i32(rule, 38, NET_FW_PROFILE2_ALL),
                ),
            ] {
                if result < 0 {
                    return Err((stage, result));
                }
            }
            if !ports.is_empty() {
                let value = Bstr::new(ports)?;
                let result = put_bstr(rule, 18, &value);
                if result < 0 {
                    return Err(("INetFwRule::put_LocalPorts", result));
                }
            }
            if !application.is_empty() {
                let value = Bstr::new(application)?;
                let result = put_bstr(rule, 12, &value);
                if result < 0 {
                    return Err(("INetFwRule::put_ApplicationName", result));
                }
            }
            let enabled = put_i16(rule, 34, VARIANT_TRUE);
            if enabled < 0 {
                return Err(("INetFwRule::put_Enabled", enabled));
            }

            type Add = unsafe extern "system" fn(*mut c_void, *mut c_void) -> HResult;
            let add: Add = core::mem::transmute(vtable_entry(firewall.rules, 8));
            let result = add(firewall.rules, rule);
            if result < 0 {
                return Err(("INetFwRules::Add", result));
            }
            Ok(())
        })();
        release(rule);
        result
    }
}

fn remove(firewall: &Firewall, name: &Bstr) -> Result<(), (&'static str, HResult)> {
    match firewall
        .item(name)
        .map_err(|status| ("INetFwRules::Item", status))?
    {
        None => return Err(("rule was not found", 0)),
        Some(existing) => unsafe {
            release(existing);
        },
    }
    unsafe {
        type Remove = unsafe extern "system" fn(*mut c_void, BstrRaw) -> HResult;
        let remove: Remove = core::mem::transmute(vtable_entry(firewall.rules, 9));
        let result = remove(firewall.rules, name.as_raw());
        if result < 0 {
            Err(("INetFwRules::Remove", result))
        } else {
            Ok(())
        }
    }
}

fn parse_direction(value: &str) -> Option<i32> {
    if value.eq_ignore_ascii_case("in") {
        Some(1)
    } else if value.eq_ignore_ascii_case("out") {
        Some(2)
    } else {
        None
    }
}

fn parse_action(value: &str) -> Option<i32> {
    if value.eq_ignore_ascii_case("block") {
        Some(0)
    } else if value.eq_ignore_ascii_case("allow") {
        Some(1)
    } else {
        None
    }
}

fn parse_protocol(value: &str) -> Option<i32> {
    if value.eq_ignore_ascii_case("tcp") {
        Some(6)
    } else if value.eq_ignore_ascii_case("udp") {
        Some(17)
    } else if value.eq_ignore_ascii_case("any") {
        Some(256)
    } else {
        None
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let action = parser.read_string(16, false)?;
            let name = parser.read_string(256, false)?;
            let direction = parser.read_string(8, true)?;
            let decision = parser.read_string(8, true)?;
            let protocol = parser.read_string(8, true)?;
            let ports = parser.read_string(256, true)?;
            let application = parser.read_string(1024, true)?;
            parser.finished().then_some((
                action,
                name,
                direction,
                decision,
                protocol,
                ports,
                application,
            ))
        })
    };

    match parsed {
        None => eprintln!(
            "Usage: firewallrule <query|add|remove> <name> <in|out|empty> <allow|block|empty> <tcp|udp|any|empty> <ports_or_empty> <application_or_empty>"
        ),
        Some((action, name, direction, decision, protocol, ports, application)) => {
            let name_bstr = Bstr::new(name);
            let firewall = Firewall::open();
            match (name_bstr, firewall) {
                (Err((stage, status)), _) | (_, Err((stage, status))) => {
                    eprintln!("{} failed: 0x{:08X}", stage, status as u32)
                }
                (Ok(name_bstr), Ok(firewall)) if action.eq_ignore_ascii_case("query") => {
                    match query(&firewall, &name_bstr) {
                        Ok(false) => println!("Rule was not found: {}", name),
                        Ok(true) => {}
                        Err((stage, status)) => {
                            eprintln!("{} failed: 0x{:08X}", stage, status as u32)
                        }
                    }
                }
                (Ok(name_bstr), Ok(firewall)) if action.eq_ignore_ascii_case("remove") => {
                    match remove(&firewall, &name_bstr) {
                        Ok(()) => println!("Firewall rule removed: {}", name),
                        Err((stage, 0)) => eprintln!("{}", stage),
                        Err((stage, status)) => {
                            eprintln!("{} failed: 0x{:08X}", stage, status as u32)
                        }
                    }
                }
                (Ok(name_bstr), Ok(firewall)) if action.eq_ignore_ascii_case("add") => {
                    match (
                        parse_direction(direction),
                        parse_action(decision),
                        parse_protocol(protocol),
                    ) {
                        (Some(direction), Some(decision), Some(protocol)) => {
                            if protocol == 256 && !ports.is_empty() {
                                eprintln!("Local ports require tcp or udp.");
                            } else {
                                match add(
                                    &firewall,
                                    &name_bstr,
                                    direction,
                                    decision,
                                    protocol,
                                    ports,
                                    application,
                                ) {
                                    Ok(()) => println!(
                                        "Firewall rule added: {}. Run remove with the same exact name to roll it back.",
                                        name
                                    ),
                                    Err((stage, 0)) => eprintln!("{}", stage),
                                    Err((stage, status)) => {
                                        eprintln!("{} failed: 0x{:08X}", stage, status as u32)
                                    }
                                }
                            }
                        }
                        _ => eprintln!("Add requires direction, decision, and protocol."),
                    }
                }
                (Ok(_), Ok(_)) => eprintln!("Unsupported action. Use query, add, or remove."),
            }
        }
    }
}
