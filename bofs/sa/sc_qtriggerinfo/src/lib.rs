//! # Service Query Trigger Info BOF
//!
//! Queries the trigger information for a specific Windows service using
//! QueryServiceConfig2A with SERVICE_CONFIG_TRIGGER_INFO (value 8).
//! Displays the number of triggers and the type and action of each trigger.
//!
//! ## MITRE ATT&CK
//! - T1007 - System Service Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Service name.

#![no_std]

use alloc::{string::String, vec};
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::*;

const SERVICE_CONFIG_TRIGGER_INFO: u32 = 8;

#[repr(C)]
struct ServiceTriggerInfo {
    c_triggers: u32,
    p_triggers: *const ServiceTrigger,
    p_reserved: *const u8,
}

#[repr(C)]
struct ServiceTrigger {
    dw_trigger_type: u32,
    dw_action: u32,
    p_trigger_subtype: *const u8, // GUID pointer
    c_data_items: u32,
    p_data_items: *const u8,
}

fn trigger_type_str(t: u32) -> &'static str {
    match t {
        1 => "DEVICE_INTERFACE_ARRIVAL",
        2 => "IP_ADDRESS_AVAILABILITY",
        3 => "DOMAIN_JOIN",
        4 => "FIREWALL_PORT_EVENT",
        5 => "GROUP_POLICY",
        6 => "NETWORK_ENDPOINT",
        7 => "CUSTOM_SYSTEM_STATE_CHANGE",
        20 => "CUSTOM",
        30 => "AGGREGATE",
        _ => "UNKNOWN",
    }
}

fn trigger_action_str(a: u32) -> &'static str {
    match a {
        1 => "SERVICE_TRIGGER_ACTION_SERVICE_START",
        2 => "SERVICE_TRIGGER_ACTION_SERVICE_STOP",
        _ => "UNKNOWN",
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let service_name = String::from(parser.get_str());

    if service_name.is_empty() {
        eprintln!("Service name is required");
        return;
    }

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        let cstr = rustbof::str::to_cstr(&hostname);
        let ptr = cstr.as_ptr() as *const u8;
        core::mem::forget(cstr);
        ptr
    };

    let svc_cstr = rustbof::str::to_cstr(&service_name);

    unsafe {
        let sc_manager = OpenSCManagerA(host_ptr, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            eprintln!("OpenSCManagerA failed: 0x{:X}", GetLastError());
            return;
        }

        let sc_service = OpenServiceA(
            sc_manager,
            svc_cstr.as_ptr() as *const u8,
            SERVICE_QUERY_CONFIG,
        );
        if sc_service.is_null() {
            eprintln!("OpenServiceA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut needed: u32 = 0;
        QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_TRIGGER_INFO,
            core::ptr::null_mut(),
            0,
            &mut needed,
        );

        if needed == 0 {
            eprintln!(
                "QueryServiceConfig2A failed to return size: 0x{:X}",
                GetLastError()
            );
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_TRIGGER_INFO,
            buf.as_mut_ptr(),
            needed,
            &mut needed,
        ) == 0
        {
            eprintln!("QueryServiceConfig2A failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let trigger_info = &*(buf.as_ptr() as *const ServiceTriggerInfo);

        println!("SERVICE_NAME: {}", service_name);
        println!("\t{:<20} : {}", "NUM_TRIGGERS", trigger_info.c_triggers);

        if !trigger_info.p_triggers.is_null() && trigger_info.c_triggers > 0 {
            let triggers = core::slice::from_raw_parts(
                trigger_info.p_triggers,
                trigger_info.c_triggers as usize,
            );
            for (i, trigger) in triggers.iter().enumerate() {
                println!(
                    "\tTRIGGER[{}]            : Type={} ({}), Action={} ({}), DataItems={}",
                    i,
                    trigger.dw_trigger_type,
                    trigger_type_str(trigger.dw_trigger_type),
                    trigger.dw_action,
                    trigger_action_str(trigger.dw_action),
                    trigger.c_data_items
                );
            }
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
    }
}
