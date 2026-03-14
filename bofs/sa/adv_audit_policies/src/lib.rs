//! # Advanced Audit Policies BOF
//!
//! Queries advanced audit policy settings using AuditQuerySystemPolicy.
//! Enumerates well-known audit subcategories and reports whether success
//! and/or failure auditing is enabled for each.
//!
//! ## MITRE ATT&CK
//! - T1562.002 - Impair Defenses: Disable Windows Event Logging
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::{eprintln, println};
#[repr(C)]
struct AuditPolicyInfo {
    audit_sub_category_guid: [u8; 16],
    auditing_information: u32,
    audit_category_guid: [u8; 16],
}

const POLICY_AUDIT_EVENT_SUCCESS: u32 = 1;
const POLICY_AUDIT_EVENT_FAILURE: u32 = 2;
const POLICY_AUDIT_EVENT_NONE: u32 = 0;
unsafe extern "system" {
    fn AuditQuerySystemPolicy(
        sub_category_guids: *const [u8; 16],
        count: u32,
        policies: *mut *mut AuditPolicyInfo,
    ) -> u8;

    fn AuditFree(buffer: *mut core::ffi::c_void);
}
struct SubCategory {
    guid: [u8; 16],
    name: &'static str,
}

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    [
        (d1 & 0xFF) as u8,
        ((d1 >> 8) & 0xFF) as u8,
        ((d1 >> 16) & 0xFF) as u8,
        ((d1 >> 24) & 0xFF) as u8,
        (d2 & 0xFF) as u8,
        ((d2 >> 8) & 0xFF) as u8,
        (d3 & 0xFF) as u8,
        ((d3 >> 8) & 0xFF) as u8,
        d4[0], d4[1], d4[2], d4[3],
        d4[4], d4[5], d4[6], d4[7],
    ]
}

static SUBCATEGORIES: &[SubCategory] = &[
    SubCategory {
        guid: guid(0x0CCE9215, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Logon",
    },
    SubCategory {
        guid: guid(0x0CCE9216, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Logoff",
    },
    SubCategory {
        guid: guid(0x0CCE9217, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Account Lockout",
    },
    SubCategory {
        guid: guid(0x0CCE921C, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Special Logon",
    },
    SubCategory {
        guid: guid(0x0CCE9235, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "User Account Management",
    },
    SubCategory {
        guid: guid(0x0CCE9237, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Security Group Management",
    },
    SubCategory {
        guid: guid(0x0CCE9236, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Computer Account Management",
    },
    SubCategory {
        guid: guid(0x0CCE9228, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Sensitive Privilege Use",
    },
    SubCategory {
        guid: guid(0x0CCE9229, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Non Sensitive Privilege Use",
    },
    SubCategory {
        guid: guid(0x0CCE921B, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "File System",
    },
    SubCategory {
        guid: guid(0x0CCE921D, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Registry",
    },
    SubCategory {
        guid: guid(0x0CCE9222, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Handle Manipulation",
    },
    SubCategory {
        guid: guid(0x0CCE922B, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Process Creation",
    },
    SubCategory {
        guid: guid(0x0CCE922C, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Process Termination",
    },
    SubCategory {
        guid: guid(0x0CCE922F, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Audit Policy Change",
    },
    SubCategory {
        guid: guid(0x0CCE9230, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Authentication Policy Change",
    },
    SubCategory {
        guid: guid(0x0CCE923B, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Directory Service Access",
    },
    SubCategory {
        guid: guid(0x0CCE923C, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Directory Service Changes",
    },
    SubCategory {
        guid: guid(0x0CCE9240, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Credential Validation",
    },
    SubCategory {
        guid: guid(0x0CCE9242, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Kerberos Authentication Service",
    },
    SubCategory {
        guid: guid(0x0CCE9241, 0xC069, 0x4A26, [0xA9, 0x68, 0x6F, 0x1A, 0x46, 0x2D, 0x79, 0x1A]),
        name: "Kerberos Service Ticket Operations",
    },
];
#[rustbof::main]
fn main() {
    println!("=== Advanced Audit Policy Settings ===\n");

    let count = SUBCATEGORIES.len() as u32;

    for sub in SUBCATEGORIES.iter() {
        unsafe {
            let mut policies: *mut AuditPolicyInfo = core::ptr::null_mut();
            let ok = AuditQuerySystemPolicy(
                &sub.guid as *const [u8; 16],
                1,
                &mut policies,
            );

            if ok == 0 || policies.is_null() {
                println!("  {}: <query failed>", sub.name);
                continue;
            }

            let info = &*policies;
            let flags = info.auditing_information;

            let success = (flags & POLICY_AUDIT_EVENT_SUCCESS) != 0;
            let failure = (flags & POLICY_AUDIT_EVENT_FAILURE) != 0;

            let status = match (success, failure) {
                (true, true) => "Success and Failure",
                (true, false) => "Success",
                (false, true) => "Failure",
                (false, false) => "No Auditing",
            };

            println!("  {}: {}", sub.name, status);

            AuditFree(policies as *mut core::ffi::c_void);
        }
    }

    println!("\n=== Audit Policy Query Complete ===");
}
