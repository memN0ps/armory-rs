//! Handleless token and integrity inspection through exact kernel profiles.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{is_kernel_pointer, read_u32, read_u64, zero},
    output::Output,
    process::{ProcessRecord, ProcessSelector, find_process, read_process_record},
    profiles::{KernelField, KernelProfile},
    session::KernelSession,
};
use core::fmt::Write;

const TOKEN_SNAPSHOT_BYTES: usize = 0x200;
const SID_ENTRY_BYTES: usize = 0x20;
const MAX_GROUPS: u32 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TokenState {
    pub(crate) token_id: u64,
    pub(crate) authentication_id: u64,
    pub(crate) privileges_present: u64,
    pub(crate) privileges_enabled: u64,
    pub(crate) privileges_default: u64,
    pub(crate) session_id: u32,
    pub(crate) user_and_group_count: u32,
    pub(crate) restricted_sid_count: u32,
    pub(crate) default_owner_index: u32,
    pub(crate) token_type: u32,
    pub(crate) impersonation_level: u32,
    pub(crate) token_flags: u32,
    pub(crate) token_in_use: u8,
    pub(crate) integrity_level_index: u32,
    pub(crate) mandatory_policy: u32,
    pub(crate) integrity_rid: u32,
    pub(crate) integrity_attributes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TokenError {
    Adapter(u32),
    InvalidProfile,
    InvalidToken,
}

impl TokenError {
    pub(crate) const fn stage(self) -> &'static str {
        match self {
            Self::Adapter(_) => "token-read",
            Self::InvalidProfile => "token-profile",
            Self::InvalidToken => "token-layout",
        }
    }

    pub(crate) const fn code(self) -> u32 {
        match self {
            Self::Adapter(code) => code,
            Self::InvalidProfile | Self::InvalidToken => 13,
        }
    }
}

pub fn inspect<A: KernelAdapter>(adapter: &mut A, selector: ProcessSelector, output: &mut Output) {
    const REQUIRED: Capabilities = Capabilities::from_bits(Capability::KernelRead as u32);

    output.line("[*] Inspecting process token and integrity state through kernel memory");
    let mut session = match KernelSession::open(adapter, REQUIRED, 0) {
        Ok(session) => session,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Token inspection failed at {} (0x{:08x}); cleanup={}",
                error.stage,
                error.code,
                complete_failed(error.cleanup_succeeded)
            );
            return;
        }
    };

    let target_pid = match selector {
        ProcessSelector::AuthenticationService => None,
        ProcessSelector::Current => Some(crate::platform::current_process_id()),
        ProcessSelector::Pid(pid) => Some(pid),
    };
    let profile = session.kernel.profile;
    let system_process = session.system_process;
    let result = inspect_inner(
        session.adapter(),
        profile,
        system_process,
        target_pid,
        output,
    );
    let close = session.close();

    if let Err((stage, code)) = result {
        let _ = writeln!(
            output,
            "[-] Token inspection failed at {stage} (0x{code:08x})"
        );
    }

    if let Err(error) = close {
        let _ = writeln!(
            output,
            "[-] Adapter close failed: {} (0x{:08x})",
            error.message(),
            error.code()
        );
        return;
    }

    if result.is_ok() {
        output.line("[+] Token inspection complete; OpenProcess was not used and no state changed");
    }
}

fn inspect_inner<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    system_process: u64,
    target_pid: Option<u32>,
    output: &mut Output,
) -> Result<(), (&'static str, u32)> {
    let (before, walked) = find_process(adapter, profile, system_process, target_pid)
        .map_err(|error| (error.stage(), error.code()))?;
    let token_address = before.token_fast_ref & !15;
    let token_before = read_state(adapter, profile, token_address)
        .map_err(|error| (error.stage(), error.code()))?;

    print_state(output, profile, &before, &token_before, walked);

    let after = read_process_record(adapter, profile, before.eprocess)
        .map_err(|error| (error.stage(), error.code()))?;
    let token_after = read_state(adapter, profile, token_address)
        .map_err(|error| (error.stage(), error.code()))?;

    if !stable_process(&before, &after) || token_before != token_after {
        return Err(("stability-compare", 1237));
    }

    output.line("[*] Stability       : process and token state matched on repeat read");

    Ok(())
}

pub(crate) fn read_state<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    token: u64,
) -> Result<TokenState, TokenError> {
    if !is_kernel_pointer(token) {
        return Err(TokenError::InvalidToken);
    }

    validate_profile(profile)?;
    let mut snapshot = [0_u8; TOKEN_SNAPSHOT_BYTES];
    adapter
        .read_kernel(token, &mut snapshot)
        .map_err(|error| TokenError::Adapter(error.code()))?;

    let mut state = TokenState {
        token_id: field_u64(&snapshot, profile, KernelField::TokenId)?,
        authentication_id: field_u64(&snapshot, profile, KernelField::TokenAuthenticationId)?,
        privileges_present: field_u64(&snapshot, profile, KernelField::TokenPrivilegesPresent)?,
        privileges_enabled: field_u64(&snapshot, profile, KernelField::TokenPrivilegesEnabled)?,
        privileges_default: field_u64(&snapshot, profile, KernelField::TokenPrivilegesDefault)?,
        session_id: field_u32(&snapshot, profile, KernelField::TokenSessionId)?,
        user_and_group_count: field_u32(&snapshot, profile, KernelField::TokenUserGroupCount)?,
        restricted_sid_count: field_u32(&snapshot, profile, KernelField::TokenRestrictedSidCount)?,
        default_owner_index: field_u32(&snapshot, profile, KernelField::TokenDefaultOwnerIndex)?,
        token_type: field_u32(&snapshot, profile, KernelField::TokenType)?,
        impersonation_level: field_u32(&snapshot, profile, KernelField::TokenImpersonationLevel)?,
        token_flags: field_u32(&snapshot, profile, KernelField::TokenFlags)?,
        token_in_use: field_u8(&snapshot, profile, KernelField::TokenInUse)?,
        integrity_level_index: field_u32(&snapshot, profile, KernelField::TokenIntegrityIndex)?,
        mandatory_policy: field_u32(&snapshot, profile, KernelField::TokenMandatoryPolicy)?,
        integrity_rid: 0,
        integrity_attributes: 0,
    };
    let groups = field_u64(&snapshot, profile, KernelField::TokenUserGroups)?;
    zero(&mut snapshot);

    if !valid_state(&state, groups) {
        return Err(TokenError::InvalidToken);
    }

    let entry_size = profile.value(KernelField::SidAndAttributesSize) as u64;
    let entry_address = groups
        .checked_add(state.integrity_level_index as u64 * entry_size)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or(TokenError::InvalidToken)?;
    let mut entry = [0_u8; SID_ENTRY_BYTES];
    adapter
        .read_kernel(entry_address, &mut entry[..entry_size as usize])
        .map_err(|error| TokenError::Adapter(error.code()))?;
    let sid_offset = profile.value(KernelField::SidAndAttributesSid) as usize;
    let attributes_offset = profile.value(KernelField::SidAndAttributesAttributes) as usize;
    let sid = read_u64(&entry, sid_offset).ok_or(TokenError::InvalidToken)?;
    state.integrity_attributes =
        read_u32(&entry, attributes_offset).ok_or(TokenError::InvalidToken)?;
    zero(&mut entry);

    if !is_kernel_pointer(sid) {
        return Err(TokenError::InvalidToken);
    }

    let mut sid_bytes = [0_u8; 12];
    adapter
        .read_kernel(sid, &mut sid_bytes)
        .map_err(|error| TokenError::Adapter(error.code()))?;
    let valid_sid = sid_bytes[..8] == [1, 1, 0, 0, 0, 0, 0, 16];
    state.integrity_rid = read_u32(&sid_bytes, 8).ok_or(TokenError::InvalidToken)?;
    zero(&mut sid_bytes);

    if !valid_sid {
        return Err(TokenError::InvalidToken);
    }

    Ok(state)
}

pub(crate) fn integrity_rid_address<A: KernelAdapter>(
    adapter: &mut A,
    profile: &KernelProfile,
    token: u64,
) -> Result<u64, TokenError> {
    if !is_kernel_pointer(token) {
        return Err(TokenError::InvalidToken);
    }

    validate_profile(profile)?;
    let mut snapshot = [0_u8; TOKEN_SNAPSHOT_BYTES];
    adapter
        .read_kernel(token, &mut snapshot)
        .map_err(|error| TokenError::Adapter(error.code()))?;
    let groups = field_u64(&snapshot, profile, KernelField::TokenUserGroups)?;
    let group_count = field_u32(&snapshot, profile, KernelField::TokenUserGroupCount)?;
    let integrity_index = field_u32(&snapshot, profile, KernelField::TokenIntegrityIndex)?;
    zero(&mut snapshot);

    if !is_kernel_pointer(groups)
        || group_count == 0
        || group_count > MAX_GROUPS
        || integrity_index >= group_count
    {
        return Err(TokenError::InvalidToken);
    }

    let entry_size = profile.value(KernelField::SidAndAttributesSize) as u64;
    let entry_address = groups
        .checked_add(integrity_index as u64 * entry_size)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or(TokenError::InvalidToken)?;
    let mut entry = [0_u8; SID_ENTRY_BYTES];
    adapter
        .read_kernel(entry_address, &mut entry[..entry_size as usize])
        .map_err(|error| TokenError::Adapter(error.code()))?;
    let sid = read_u64(
        &entry,
        profile.value(KernelField::SidAndAttributesSid) as usize,
    )
    .ok_or(TokenError::InvalidToken)?;
    zero(&mut entry);
    let address = sid
        .checked_add(8)
        .filter(|address| is_kernel_pointer(*address))
        .ok_or(TokenError::InvalidToken)?;
    let mut sid_bytes = [0_u8; 12];
    adapter
        .read_kernel(sid, &mut sid_bytes)
        .map_err(|error| TokenError::Adapter(error.code()))?;
    let valid = sid_bytes[..8] == [1, 1, 0, 0, 0, 0, 0, 16];
    zero(&mut sid_bytes);

    if !valid {
        return Err(TokenError::InvalidToken);
    }

    Ok(address)
}

fn validate_profile(profile: &KernelProfile) -> Result<(), TokenError> {
    for (field, width) in [
        (KernelField::TokenId, 8),
        (KernelField::TokenAuthenticationId, 8),
        (KernelField::TokenPrivilegesPresent, 8),
        (KernelField::TokenPrivilegesEnabled, 8),
        (KernelField::TokenPrivilegesDefault, 8),
        (KernelField::TokenSessionId, 4),
        (KernelField::TokenUserGroupCount, 4),
        (KernelField::TokenRestrictedSidCount, 4),
        (KernelField::TokenDefaultOwnerIndex, 4),
        (KernelField::TokenUserGroups, 8),
        (KernelField::TokenType, 4),
        (KernelField::TokenImpersonationLevel, 4),
        (KernelField::TokenFlags, 4),
        (KernelField::TokenInUse, 1),
        (KernelField::TokenIntegrityIndex, 4),
        (KernelField::TokenMandatoryPolicy, 4),
    ] {
        if profile.value(field) as usize + width > TOKEN_SNAPSHOT_BYTES {
            return Err(TokenError::InvalidProfile);
        }
    }

    let entry_size = profile.value(KernelField::SidAndAttributesSize) as usize;
    let sid = profile.value(KernelField::SidAndAttributesSid) as usize;
    let attributes = profile.value(KernelField::SidAndAttributesAttributes) as usize;

    if entry_size == 0
        || entry_size > SID_ENTRY_BYTES
        || sid + 8 > entry_size
        || attributes + 4 > entry_size
    {
        return Err(TokenError::InvalidProfile);
    }

    Ok(())
}

fn valid_state(state: &TokenState, groups: u64) -> bool {
    matches!(state.token_type, 1 | 2)
        && state.token_in_use <= 1
        && state.user_and_group_count != 0
        && state.user_and_group_count <= MAX_GROUPS
        && state.integrity_level_index < state.user_and_group_count
        && state.default_owner_index < state.user_and_group_count
        && is_kernel_pointer(groups)
}

fn field_u64(bytes: &[u8], profile: &KernelProfile, field: KernelField) -> Result<u64, TokenError> {
    read_u64(bytes, profile.value(field) as usize).ok_or(TokenError::InvalidProfile)
}

fn field_u32(bytes: &[u8], profile: &KernelProfile, field: KernelField) -> Result<u32, TokenError> {
    read_u32(bytes, profile.value(field) as usize).ok_or(TokenError::InvalidProfile)
}

fn field_u8(bytes: &[u8], profile: &KernelProfile, field: KernelField) -> Result<u8, TokenError> {
    bytes
        .get(profile.value(field) as usize)
        .copied()
        .ok_or(TokenError::InvalidProfile)
}

fn stable_process(before: &ProcessRecord, after: &ProcessRecord) -> bool {
    before.pid == after.pid
        && before.forward_link == after.forward_link
        && before.backward_link == after.backward_link
        && before.token_fast_ref & !15 == after.token_fast_ref & !15
}

fn print_state(
    output: &mut Output,
    profile: &KernelProfile,
    process: &ProcessRecord,
    token: &TokenState,
    walked: usize,
) {
    let _ = writeln!(
        output,
        "[*] Kernel profile  : {} exact PE and PDB match",
        profile.display_build
    );
    let _ = writeln!(
        output,
        "[*] Process         : pid={} image={} walked={}",
        process.pid,
        process.display_name(),
        walked
    );
    let _ = writeln!(
        output,
        "[*] Token           : type={} session={} in-use={} refbits={}",
        token_type(token.token_type),
        token.session_id,
        token.token_in_use,
        process.token_fast_ref & 15
    );
    let _ = writeln!(
        output,
        "[*] Integrity       : level={} rid=0x{:04x} policy=0x{:08x} attributes=0x{:08x}",
        integrity_name(token.integrity_rid),
        token.integrity_rid,
        token.mandatory_policy,
        token.integrity_attributes
    );
    let _ = writeln!(
        output,
        "[*] Privileges      : present={} enabled={} default={}",
        token.privileges_present.count_ones(),
        token.privileges_enabled.count_ones(),
        token.privileges_default.count_ones()
    );
    let _ = writeln!(
        output,
        "[*] Bounds          : groups={} restricted={} integrity-index={}",
        token.user_and_group_count, token.restricted_sid_count, token.integrity_level_index
    );
}

const fn token_type(value: u32) -> &'static str {
    match value {
        1 => "primary",
        2 => "impersonation",
        _ => "invalid",
    }
}

const fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000..=0x0fff => "untrusted",
        0x1000..=0x1fff => "low",
        0x2000..=0x2fff => "medium",
        0x3000..=0x3fff => "high",
        0x4000..=0x4fff => "system",
        _ => "protected",
    }
}

const fn complete_failed(value: bool) -> &'static str {
    if value { "complete" } else { "failed" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_token_types() {
        assert_eq!(token_type(1), "primary");
        assert_eq!(token_type(2), "impersonation");
        assert_eq!(token_type(3), "invalid");
    }

    #[test]
    fn names_integrity_levels() {
        assert_eq!(integrity_name(0), "untrusted");
        assert_eq!(integrity_name(0x1000), "low");
        assert_eq!(integrity_name(0x2000), "medium");
        assert_eq!(integrity_name(0x3000), "high");
        assert_eq!(integrity_name(0x4000), "system");
        assert_eq!(integrity_name(0x5000), "protected");
    }
}
