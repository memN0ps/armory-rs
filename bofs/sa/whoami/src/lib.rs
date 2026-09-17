//! # Identity BOF
//!
//! Reports the current user, SID, token groups, integrity level, and token
//! privileges.
//!
//! ## Arguments
//! - None.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//! - T1069.001 - Permission Groups Discovery: Local Groups

#![no_std]

use alloc::format;
use alloc::{vec, vec::Vec};
use core::ptr::null;

use rustbof::str::from_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Security::{
    LookupAccountSidW, SE_PRIVILEGE_ENABLED, SidTypeAlias, SidTypeGroup, SidTypeLabel,
    SidTypeWellKnownGroup, TOKEN_GROUPS, TOKEN_PRIVILEGES, TokenGroups, TokenPrivileges,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;

use crate::helpers::{
    format_group_attrs, get_token_info, get_user_sid, get_username, lookup_privilege_desc,
    lookup_privilege_name, sid_to_string, sid_type_str,
};

mod helpers;

#[rustbof::main]
fn main() {
    show_user();
    show_groups();
    show_privileges();
}

fn show_user() {
    let username = get_username();
    let sid = get_user_sid();

    let w1 = username.chars().count().max(9);
    let w2 = sid.chars().count().max(3);

    println!("USER INFORMATION");
    println!("----------------\n");
    println!("{:<w1$} {}", "User Name", "SID", w1 = w1);
    println!("{} {}", "=".repeat(w1), "=".repeat(w2));
    println!("{:<w1$} {}", username, sid, w1 = w1);
}

fn show_groups() {
    let Some(info) = get_token_info(TokenGroups) else {
        eprintln!("Failed to get token groups");
        return;
    };

    let groups = unsafe {
        let ptr = info.as_ptr() as *const TOKEN_GROUPS;
        core::slice::from_raw_parts((*ptr).Groups.as_ptr(), (*ptr).GroupCount as usize)
    };

    let mut rows = Vec::new();
    let mut name_buffer = vec![0u16; 256];
    let mut domain_buffer = vec![0u16; 256];

    for group in groups {
        let mut name_len = name_buffer.len() as u32;
        let mut domain_len = domain_buffer.len() as u32;
        let mut sid_type = 0;

        let result = unsafe {
            LookupAccountSidW(
                null(),
                group.Sid,
                name_buffer.as_mut_ptr(),
                &mut name_len,
                domain_buffer.as_mut_ptr(),
                &mut domain_len,
                &mut sid_type,
            )
        };

        if result == FALSE {
            continue;
        }

        if sid_type != SidTypeWellKnownGroup
            && sid_type != SidTypeAlias
            && sid_type != SidTypeLabel
            && sid_type != SidTypeGroup
            || (group.Attributes & SE_GROUP_LOGON_ID as u32) != 0
        {
            continue;
        }

        let name = from_wide(&name_buffer);
        let domain = from_wide(&domain_buffer);
        let display = if domain.is_empty() {
            name
        } else {
            format!("{}\\{}", domain, name)
        };

        rows.push((
            display,
            sid_type_str(sid_type),
            sid_to_string(group.Sid),
            format_group_attrs(group.Attributes),
        ));
    }

    if rows.is_empty() {
        return;
    }

    let w1 = rows
        .iter()
        .map(|r| r.0.chars().count())
        .max()
        .unwrap_or(0)
        .max(10);
    let w2 = rows
        .iter()
        .map(|r| r.1.chars().count())
        .max()
        .unwrap_or(0)
        .max(4);
    let w3 = rows
        .iter()
        .map(|r| r.2.chars().count())
        .max()
        .unwrap_or(0)
        .max(3);
    let w4 = rows
        .iter()
        .map(|r| r.3.chars().count())
        .max()
        .unwrap_or(0)
        .max(10);

    println!("\n\nGROUP INFORMATION");
    println!("-----------------\n");
    println!(
        "{:<w1$} {:<w2$} {:<w3$} {}",
        "Group Name",
        "Type",
        "SID",
        "Attributes",
        w1 = w1,
        w2 = w2,
        w3 = w3
    );
    println!(
        "{} {} {} {}",
        "=".repeat(w1),
        "=".repeat(w2),
        "=".repeat(w3),
        "=".repeat(w4)
    );

    for (name, kind, sid, attrs) in rows {
        println!(
            "{:<w1$} {:<w2$} {:<w3$} {}",
            name,
            kind,
            sid,
            attrs,
            w1 = w1,
            w2 = w2,
            w3 = w3
        );
    }
}

fn show_privileges() {
    let Some(info) = get_token_info(TokenPrivileges) else {
        eprintln!("Failed to get token privileges");
        return;
    };

    let privileges = unsafe {
        let ptr = info.as_ptr() as *const TOKEN_PRIVILEGES;
        core::slice::from_raw_parts((*ptr).Privileges.as_ptr(), (*ptr).PrivilegeCount as usize)
    };

    let mut rows = Vec::new();
    for privilege in privileges {
        let name = lookup_privilege_name(&privilege.Luid);
        let desc = lookup_privilege_desc(&name);
        let state = if (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0 {
            "Enabled"
        } else {
            "Disabled"
        };

        rows.push((name, desc, state));
    }

    if rows.is_empty() {
        return;
    }

    let w1 = rows
        .iter()
        .map(|r| r.0.chars().count())
        .max()
        .unwrap_or(0)
        .max(14);
    let w2 = rows
        .iter()
        .map(|r| r.1.chars().count())
        .max()
        .unwrap_or(0)
        .max(11);
    let w3 = rows
        .iter()
        .map(|r| r.2.chars().count())
        .max()
        .unwrap_or(0)
        .max(5);

    println!("\n\nPRIVILEGES INFORMATION");
    println!("----------------------\n");
    println!(
        "{:<w1$} {:<w2$} {}",
        "Privilege Name",
        "Description",
        "State",
        w1 = w1,
        w2 = w2
    );
    println!("{} {} {}", "=".repeat(w1), "=".repeat(w2), "=".repeat(w3));

    for (name, desc, state) in rows {
        println!("{:<w1$} {:<w2$} {}", name, desc, state, w1 = w1, w2 = w2);
    }
}
