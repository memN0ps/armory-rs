//! Minimal Windows platform queries used before a driver adapter is opened.

#[cfg(not(test))]
use core::{ffi::c_void, mem::size_of};

#[cfg(not(test))]
const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;
#[cfg(not(test))]
const SYSTEM_ISOLATED_USER_MODE_INFORMATION: u32 = 165;

const CODE_INTEGRITY_ENABLED: u32 = 0x0000_0001;
const TEST_SIGNING_ENABLED: u32 = 0x0000_0002;
const USER_MODE_CODE_INTEGRITY_ENABLED: u32 = 0x0000_0004;
const USER_MODE_CODE_INTEGRITY_AUDIT: u32 = 0x0000_0008;
const HVCI_ENABLED: u32 = 0x0000_0400;
const HVCI_AUDIT: u32 = 0x0000_0800;
const HVCI_STRICT: u32 = 0x0000_1000;
const HVCI_ISOLATED_USER_MODE: u32 = 0x0000_2000;
const HVCI_MASK: u32 = HVCI_ENABLED | HVCI_AUDIT | HVCI_STRICT | HVCI_ISOLATED_USER_MODE;

const SECURE_KERNEL_RUNNING: u8 = 0x01;
const ISOLATED_HVCI_ENABLED: u8 = 0x02;
const TRUSTLET_RUNNING: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    #[cfg(not(test))]
    Version(i32),
    #[cfg(not(test))]
    CodeIntegrity(i32),
    #[cfg(not(test))]
    IsolatedUserMode(i32),
    #[cfg(not(test))]
    InvalidResponse,
    #[cfg(test)]
    Unavailable,
}

impl PlatformError {
    pub const fn stage(self) -> &'static str {
        match self {
            #[cfg(not(test))]
            Self::Version(_) => "os-version",
            #[cfg(not(test))]
            Self::CodeIntegrity(_) => "code-integrity-query",
            #[cfg(not(test))]
            Self::IsolatedUserMode(_) => "isolated-user-mode-query",
            #[cfg(not(test))]
            Self::InvalidResponse => "invalid-system-response",
            #[cfg(test)]
            Self::Unavailable => "platform-query-unavailable",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            #[cfg(not(test))]
            Self::Version(status)
            | Self::CodeIntegrity(status)
            | Self::IsolatedUserMode(status) => status as u32,
            #[cfg(not(test))]
            Self::InvalidResponse => 13,
            #[cfg(test)]
            Self::Unavailable => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostProtection {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub code_integrity_options: u32,
    pub isolated_primary_flags: u8,
    pub isolated_secondary_flags: u8,
}

impl HostProtection {
    pub const fn kernel_code_integrity_enabled(self) -> bool {
        self.code_integrity_options & CODE_INTEGRITY_ENABLED != 0
    }

    pub const fn test_signing_enabled(self) -> bool {
        self.code_integrity_options & TEST_SIGNING_ENABLED != 0
    }

    pub const fn user_mode_code_integrity_enabled(self) -> bool {
        self.code_integrity_options & USER_MODE_CODE_INTEGRITY_ENABLED != 0
    }

    pub const fn user_mode_code_integrity_audit(self) -> bool {
        self.code_integrity_options & USER_MODE_CODE_INTEGRITY_AUDIT != 0
    }

    pub const fn hvci_enabled(self) -> bool {
        self.code_integrity_options & HVCI_MASK != 0
            || self.isolated_primary_flags & ISOLATED_HVCI_ENABLED != 0
    }

    pub const fn secure_kernel_running(self) -> bool {
        self.isolated_primary_flags & SECURE_KERNEL_RUNNING != 0
    }

    pub const fn trustlet_running(self) -> bool {
        self.isolated_secondary_flags & TRUSTLET_RUNNING != 0
    }

    pub const fn dse_mutation_supported(self) -> bool {
        !self.hvci_enabled() && !self.secure_kernel_running()
    }
}

#[cfg(not(test))]
#[repr(C)]
struct OsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

#[cfg(not(test))]
#[repr(C)]
struct CodeIntegrityInformation {
    length: u32,
    options: u32,
}

#[cfg(not(test))]
#[repr(C)]
struct IsolatedUserModeInformation {
    primary_flags: u8,
    secondary_flags: u8,
    reserved: [u8; 6],
    reserved2: u64,
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "GetCurrentProcessId"]
    fn get_current_process_id() -> u32;

    #[link_name = "RtlGetVersion"]
    fn rtl_get_version(version: *mut c_void) -> i32;

    #[link_name = "NtQuerySystemInformation"]
    fn nt_query_system_information(
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[cfg(not(test))]
pub fn current_process_id() -> u32 {
    // SAFETY: GetCurrentProcessId takes no arguments and has no failure mode.
    unsafe { get_current_process_id() }
}

#[cfg(test)]
pub const fn current_process_id() -> u32 {
    4242
}

#[cfg(not(test))]
pub fn query_host_protection() -> Result<HostProtection, PlatformError> {
    let mut version = OsVersionInfo {
        size: size_of::<OsVersionInfo>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };

    // SAFETY: `version` is a writable, correctly sized OS version structure
    // that remains live for the complete call.
    let status = unsafe { rtl_get_version((&mut version as *mut OsVersionInfo).cast()) };

    if status < 0 {
        return Err(PlatformError::Version(status));
    }

    if version.build == 0 {
        return Err(PlatformError::InvalidResponse);
    }

    let mut code_integrity = CodeIntegrityInformation {
        length: size_of::<CodeIntegrityInformation>() as u32,
        options: 0,
    };
    let mut returned = 0_u32;

    // SAFETY: `code_integrity` is writable for the exact advertised size.
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            (&mut code_integrity as *mut CodeIntegrityInformation).cast(),
            size_of::<CodeIntegrityInformation>() as u32,
            &mut returned,
        )
    };

    if status < 0 {
        return Err(PlatformError::CodeIntegrity(status));
    }

    if code_integrity.length as usize != size_of::<CodeIntegrityInformation>() {
        return Err(PlatformError::InvalidResponse);
    }

    let mut isolated = IsolatedUserModeInformation {
        primary_flags: 0,
        secondary_flags: 0,
        reserved: [0; 6],
        reserved2: 0,
    };
    returned = 0;

    // SAFETY: `isolated` is writable for the exact advertised size.
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_ISOLATED_USER_MODE_INFORMATION,
            (&mut isolated as *mut IsolatedUserModeInformation).cast(),
            size_of::<IsolatedUserModeInformation>() as u32,
            &mut returned,
        )
    };

    if status < 0 {
        return Err(PlatformError::IsolatedUserMode(status));
    }

    if returned != 0 && returned as usize != size_of::<IsolatedUserModeInformation>() {
        return Err(PlatformError::InvalidResponse);
    }

    Ok(HostProtection {
        major: version.major,
        minor: version.minor,
        build: version.build,
        code_integrity_options: code_integrity.options,
        isolated_primary_flags: isolated.primary_flags,
        isolated_secondary_flags: isolated.secondary_flags,
    })
}

#[cfg(test)]
pub fn query_host_protection() -> Result<HostProtection, PlatformError> {
    Err(PlatformError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_virtualization_protections() {
        let protection = HostProtection {
            major: 10,
            minor: 0,
            build: 22631,
            code_integrity_options: CODE_INTEGRITY_ENABLED | HVCI_ENABLED,
            isolated_primary_flags: SECURE_KERNEL_RUNNING | ISOLATED_HVCI_ENABLED,
            isolated_secondary_flags: TRUSTLET_RUNNING,
        };

        assert!(protection.kernel_code_integrity_enabled());
        assert!(protection.hvci_enabled());
        assert!(protection.secure_kernel_running());
        assert!(protection.trustlet_running());
        assert!(!protection.dse_mutation_supported());
    }

    #[test]
    fn allows_dse_only_without_vbs_or_hvci() {
        let protection = HostProtection {
            major: 10,
            minor: 0,
            build: 19045,
            code_integrity_options: CODE_INTEGRITY_ENABLED,
            isolated_primary_flags: 0,
            isolated_secondary_flags: 0,
        };

        assert!(protection.dse_mutation_supported());
        assert!(!protection.test_signing_enabled());
        assert!(!protection.user_mode_code_integrity_enabled());
        assert!(!protection.user_mode_code_integrity_audit());
    }
}
