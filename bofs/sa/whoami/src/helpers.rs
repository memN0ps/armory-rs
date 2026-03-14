use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{null, null_mut};

use rustbof::str::{from_wide, to_wide};
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authentication::Identity::{
    GetUserNameExA, NameSamCompatible
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, GetLastError, 
    LUID, LocalFree
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupPrivilegeDisplayNameW, LookupPrivilegeNameW,
    SidTypeAlias, SidTypeGroup, SidTypeLabel, SidTypeWellKnownGroup,
    TokenUser, TOKEN_INFORMATION_CLASS, TOKEN_READ, TOKEN_USER,
};
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY,
};

pub fn get_username() -> String {
    let mut buf = vec![0u8; 256];
    let mut len = buf.len() as u32;

    if unsafe { GetUserNameExA(NameSamCompatible, buf.as_mut_ptr(), &mut len) } != 0 {
        buf.truncate(len as usize);
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::new()
    }
}

pub fn get_user_sid() -> String {
    get_token_info(TokenUser)
        .map(|info| {
            let user = unsafe { &*(info.as_ptr() as *const TOKEN_USER) };
            sid_to_string(user.User.Sid)
        })
        .unwrap_or_default()
}

pub fn get_token_info(class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u8>> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(-1isize as *mut c_void, TOKEN_READ, &mut token) == FALSE {
            return None;
        }

        let mut len = 0u32;
        GetTokenInformation(token, class, null_mut(), 0, &mut len);

        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0 {
            CloseHandle(token);
            return None;
        }

        let mut buf = vec![0u8; len as usize];
        let result = GetTokenInformation(token, class, buf.as_mut_ptr() as _, len, &mut len);
        CloseHandle(token);

        if result != FALSE { 
            Some(buf) 
        } else { 
            None 
        }
    }
}

pub fn sid_to_string(sid: *mut c_void) -> String {
    unsafe {
        let mut ptr: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut ptr) == FALSE {
            return String::new();
        }

        let mut len = 0;
        let sid = {
            while *ptr.add(len) != 0 {
                len += 1;
            }

            String::from_utf16_lossy(core::slice::from_raw_parts(ptr, len))
        };

        LocalFree(ptr as _);
        sid
    }
}

pub fn lookup_privilege_name(luid: &LUID) -> String {
    unsafe {
        let mut len = 0u32;
        LookupPrivilegeNameW(null(), luid as *const _ as *mut _, null_mut(), &mut len);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0 {
            return String::new();
        }

        let mut buf = vec![0u16; len as usize];
        if LookupPrivilegeNameW(null(), luid as *const _ as *mut _, buf.as_mut_ptr(), &mut len) != FALSE {
            from_wide(&buf)
        } else {
            String::new()
        }
    }
}

pub fn lookup_privilege_desc(name: &str) -> String {
    let name = to_wide(name);

    unsafe {
        let mut len = 0u32;
        let mut lang = 0u32;
        LookupPrivilegeDisplayNameW(null(), name.as_ptr(), null_mut(), &mut len, &mut lang);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0 {
            return String::new();
        }

        let mut buf = vec![0u16; len as usize];
        if LookupPrivilegeDisplayNameW(null(), name.as_ptr(), buf.as_mut_ptr(), &mut len, &mut lang) != FALSE {
            from_wide(&buf)
        } else {
            String::new()
        }
    }
}

#[allow(non_upper_case_globals)]
pub fn sid_type_str(t: i32) -> &'static str {
    match t {
        SidTypeWellKnownGroup => "Well-known group",
        SidTypeAlias => "Alias",
        SidTypeLabel => "Label",
        SidTypeGroup => "Group",
        _ => "Other",
    }
}

pub fn format_group_attrs(attrs: u32) -> String {
    if (attrs & SE_GROUP_USE_FOR_DENY_ONLY as u32) != 0 {
        return String::from("Group used for deny only");
    }

    let mut s = String::new();
    if (attrs & SE_GROUP_MANDATORY as u32) != 0 {
        s.push_str("Mandatory group, ");
    }
    
    if (attrs & SE_GROUP_ENABLED_BY_DEFAULT as u32) != 0 {
        s.push_str("Enabled by default, ");
    }
    
    if (attrs & SE_GROUP_ENABLED as u32) != 0 {
        s.push_str("Enabled group");
    }

    if (attrs & SE_GROUP_OWNER as u32) != 0 {
        if !s.is_empty() && !s.ends_with(", ") {
            s.push_str(", ");
        }
        s.push_str("Group owner");
    }
    
    s
}
