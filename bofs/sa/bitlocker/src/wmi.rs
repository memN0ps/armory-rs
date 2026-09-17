//! Local COM and WMI support for this BOF.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::ffi::c_void;

type HResult = i32;
type BstrRaw = *mut u16;

const S_OK: HResult = 0;
const S_FALSE: HResult = 1;
const RPC_E_CHANGED_MODE: HResult = 0x80010106u32 as i32;
const RPC_E_TOO_LATE: HResult = 0x80010119u32 as i32;
const WBEM_S_NO_MORE_DATA: HResult = 0x00040005;
const WBEM_S_TIMEDOUT: HResult = 0x00040004;
const WBEM_FLAG_RETURN_IMMEDIATELY: i32 = 0x10;
const WBEM_FLAG_FORWARD_ONLY: i32 = 0x20;

const COINIT_MULTITHREADED: u32 = 0;
const CLSCTX_INPROC_SERVER: u32 = 1;
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;

const VT_EMPTY: u16 = 0;
const VT_NULL: u16 = 1;
const VT_I2: u16 = 2;
const VT_I4: u16 = 3;
const VT_BSTR: u16 = 8;
const VT_BOOL: u16 = 11;
const VT_I1: u16 = 16;
const VT_UI1: u16 = 17;
const VT_UI2: u16 = 18;
const VT_UI4: u16 = 19;
const VT_I8: u16 = 20;
const VT_UI8: u16 = 21;
const VT_INT: u16 = 22;
const VT_UINT: u16 = 23;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct Variant {
    variant_type: u16,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    data: [u64; 2],
}

unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency: u32) -> HResult;
    fn CoInitializeSecurity(
        security_descriptor: *mut c_void,
        authentication_services: i32,
        services: *mut c_void,
        reserved1: *mut c_void,
        authentication_level: u32,
        impersonation_level: u32,
        authentication_list: *mut c_void,
        capabilities: u32,
        reserved3: *mut c_void,
    ) -> HResult;
    fn CoCreateInstance(
        class_id: *const Guid,
        outer: *mut c_void,
        context: u32,
        interface_id: *const Guid,
        object: *mut *mut c_void,
    ) -> HResult;
    fn CoSetProxyBlanket(
        proxy: *mut c_void,
        authentication_service: u32,
        authorization_service: u32,
        principal_name: *mut u16,
        authentication_level: u32,
        impersonation_level: u32,
        authentication_info: *mut c_void,
        capabilities: u32,
    ) -> HResult;
    fn CoUninitialize();
    fn SysAllocStringLen(source: *const u16, length: u32) -> BstrRaw;
    fn SysFreeString(value: BstrRaw);
    fn SysStringLen(value: BstrRaw) -> u32;
    fn VariantClear(value: *mut Variant) -> HResult;
}

const CLSID_WBEM_LOCATOR: Guid = Guid {
    data1: 0x4590F811,
    data2: 0x1D3A,
    data3: 0x11D0,
    data4: [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};

const IID_IWBEM_LOCATOR: Guid = Guid {
    data1: 0xDC12A687,
    data2: 0x737F,
    data3: 0x11CF,
    data4: [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};

pub struct WmiError {
    pub stage: &'static str,
    pub code: HResult,
}

pub enum Value {
    Empty,
    Text(String),
    Signed(i64),
    Unsigned(u64),
    Boolean(bool),
    Unsupported,
}

struct Apartment {
    uninitialize: bool,
}

impl Apartment {
    fn initialize() -> Result<Self, WmiError> {
        unsafe {
            let result = CoInitializeEx(core::ptr::null_mut(), COINIT_MULTITHREADED);
            let uninitialize = result == S_OK || result == S_FALSE;
            if result < 0 && result != RPC_E_CHANGED_MODE {
                return Err(WmiError {
                    stage: "CoInitializeEx",
                    code: result,
                });
            }

            let result = CoInitializeSecurity(
                core::ptr::null_mut(),
                -1,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            );
            if result < 0 && result != RPC_E_TOO_LATE {
                if uninitialize {
                    CoUninitialize();
                }
                return Err(WmiError {
                    stage: "CoInitializeSecurity",
                    code: result,
                });
            }

            Ok(Self { uninitialize })
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

struct Bstr(BstrRaw);

impl Bstr {
    fn new(value: &str) -> Result<Self, WmiError> {
        let wide: Vec<u16> = value.encode_utf16().collect();
        if wide.len() > u32::MAX as usize {
            return Err(WmiError {
                stage: "BSTR length",
                code: 0x80070057u32 as i32,
            });
        }

        let raw = unsafe { SysAllocStringLen(wide.as_ptr(), wide.len() as u32) };
        if raw.is_null() {
            Err(WmiError {
                stage: "SysAllocStringLen",
                code: 0x8007000Eu32 as i32,
            })
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) };
    }
}

struct ComPtr(*mut c_void);

impl ComPtr {
    fn new(pointer: *mut c_void, stage: &'static str) -> Result<Self, WmiError> {
        if pointer.is_null() {
            Err(WmiError {
                stage,
                code: 0x80004003u32 as i32,
            })
        } else {
            Ok(Self(pointer))
        }
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    core::mem::transmute(vtable_entry(self.0, 2));
                release(self.0);
            }
        }
    }
}

unsafe fn vtable_entry(object: *mut c_void, index: usize) -> *const c_void {
    // SAFETY: Every caller supplies a live COM interface pointer. COM places a
    // pointer to an immutable vtable at offset zero, and each requested index
    // is fixed by the interface ABI used by that caller.
    let table = unsafe { *(object as *mut *mut *const c_void) };
    unsafe { *table.add(index) }
}

pub struct Session {
    services: ComPtr,
    _locator: ComPtr,
    _apartment: Apartment,
}

impl Session {
    pub fn connect(namespace: &str) -> Result<Self, WmiError> {
        let apartment = Apartment::initialize()?;
        let mut locator = core::ptr::null_mut();
        let result = unsafe {
            CoCreateInstance(
                &CLSID_WBEM_LOCATOR,
                core::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_IWBEM_LOCATOR,
                &mut locator,
            )
        };
        if result < 0 {
            return Err(WmiError {
                stage: "CoCreateInstance",
                code: result,
            });
        }
        let locator = ComPtr::new(locator, "IWbemLocator")?;
        let namespace = Bstr::new(namespace)?;
        let mut services = core::ptr::null_mut();

        unsafe {
            type ConnectServer = unsafe extern "system" fn(
                *mut c_void,
                BstrRaw,
                BstrRaw,
                BstrRaw,
                BstrRaw,
                i32,
                BstrRaw,
                *mut c_void,
                *mut *mut c_void,
            ) -> HResult;
            let connect: ConnectServer = core::mem::transmute(vtable_entry(locator.as_ptr(), 3));
            let result = connect(
                locator.as_ptr(),
                namespace.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut services,
            );
            if result < 0 {
                return Err(WmiError {
                    stage: "IWbemLocator::ConnectServer",
                    code: result,
                });
            }
        }

        let services = ComPtr::new(services, "IWbemServices")?;
        let result = unsafe {
            CoSetProxyBlanket(
                services.as_ptr(),
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                core::ptr::null_mut(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                core::ptr::null_mut(),
                0,
            )
        };
        if result < 0 {
            return Err(WmiError {
                stage: "CoSetProxyBlanket",
                code: result,
            });
        }

        Ok(Self {
            services,
            _locator: locator,
            _apartment: apartment,
        })
    }

    pub fn query(&self, query: &str) -> Result<Query, WmiError> {
        let language = Bstr::new("WQL")?;
        let query_text = Bstr::new(query)?;
        let mut enumerator = core::ptr::null_mut();

        unsafe {
            type ExecQuery = unsafe extern "system" fn(
                *mut c_void,
                BstrRaw,
                BstrRaw,
                i32,
                *mut c_void,
                *mut *mut c_void,
            ) -> HResult;
            let exec: ExecQuery = core::mem::transmute(vtable_entry(self.services.as_ptr(), 20));
            let result = exec(
                self.services.as_ptr(),
                language.0,
                query_text.0,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                core::ptr::null_mut(),
                &mut enumerator,
            );
            if result < 0 {
                return Err(WmiError {
                    stage: "IWbemServices::ExecQuery",
                    code: result,
                });
            }
        }

        Ok(Query {
            enumerator: ComPtr::new(enumerator, "IEnumWbemClassObject")?,
        })
    }
}

pub struct Query {
    enumerator: ComPtr,
}

impl Query {
    pub fn next(&mut self, timeout_ms: u32) -> Result<Option<Object>, WmiError> {
        let mut object = core::ptr::null_mut();
        let mut returned = 0u32;
        let result = unsafe {
            type Next = unsafe extern "system" fn(
                *mut c_void,
                i32,
                u32,
                *mut *mut c_void,
                *mut u32,
            ) -> HResult;
            let next: Next = core::mem::transmute(vtable_entry(self.enumerator.as_ptr(), 4));
            next(
                self.enumerator.as_ptr(),
                timeout_ms as i32,
                1,
                &mut object,
                &mut returned,
            )
        };

        if result == WBEM_S_TIMEDOUT {
            return Err(WmiError {
                stage: "IEnumWbemClassObject::Next timeout",
                code: result,
            });
        }
        if result == S_FALSE || result == WBEM_S_NO_MORE_DATA || returned == 0 {
            return Ok(None);
        }
        if result < 0 {
            return Err(WmiError {
                stage: "IEnumWbemClassObject::Next",
                code: result,
            });
        }

        Ok(Some(Object {
            object: ComPtr::new(object, "IWbemClassObject")?,
        }))
    }
}

pub struct Object {
    object: ComPtr,
}

impl Object {
    pub fn get(&self, name: &str) -> Result<Value, WmiError> {
        let name: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        let mut value: Variant = unsafe { core::mem::zeroed() };
        let result = unsafe {
            type Get = unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                i32,
                *mut Variant,
                *mut i32,
                *mut i32,
            ) -> HResult;
            let get: Get = core::mem::transmute(vtable_entry(self.object.as_ptr(), 4));
            get(
                self.object.as_ptr(),
                name.as_ptr(),
                0,
                &mut value,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(WmiError {
                stage: "IWbemClassObject::Get",
                code: result,
            });
        }

        let output = unsafe { value_to_owned(&value) };
        unsafe { VariantClear(&mut value) };
        Ok(output)
    }
}

unsafe fn bstr_to_string(value: BstrRaw) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let length = unsafe { SysStringLen(value) } as usize;
    if length > 32768 {
        return None;
    }
    let text = unsafe { core::slice::from_raw_parts(value, length) };
    Some(String::from_utf16_lossy(text))
}

unsafe fn value_to_owned(value: &Variant) -> Value {
    match value.variant_type {
        VT_EMPTY | VT_NULL => Value::Empty,
        VT_BSTR => unsafe {
            bstr_to_string(value.data[0] as BstrRaw)
                .map(Value::Text)
                .unwrap_or(Value::Empty)
        },
        VT_BOOL => Value::Boolean(value.data[0] as i16 != 0),
        VT_I1 => Value::Signed(value.data[0] as i8 as i64),
        VT_I2 => Value::Signed(value.data[0] as i16 as i64),
        VT_I4 | VT_INT => Value::Signed(value.data[0] as i32 as i64),
        VT_I8 => Value::Signed(value.data[0] as i64),
        VT_UI1 => Value::Unsigned(value.data[0] as u8 as u64),
        VT_UI2 => Value::Unsigned(value.data[0] as u16 as u64),
        VT_UI4 | VT_UINT => Value::Unsigned(value.data[0] as u32 as u64),
        VT_UI8 => Value::Unsigned(value.data[0]),
        _ => Value::Unsupported,
    }
}
