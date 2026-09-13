//! Command parsing and dispatch.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    args::{ArgumentError, Arguments},
    bytes::zero,
    callback::{self, CallbackAction, CallbackKind, TargetSpec},
    credentials::{self, CredentialAction},
    dse::{self, DseAction},
    etw_ti::{self, EtwTiAction},
    kernel::{KERNEL_HEADER_BYTES, verify_loaded_kernel},
    minifilter::{self, MinifilterAction, MinifilterTarget},
    modules::SystemModules,
    object_callback::{self, ObjectAction, ObjectKind, ObjectTarget},
    output::Output,
    platform,
    ppl::{self, PplAction},
    process::{self, ProcessSelector},
    process_control::{self, ProtectionAction},
    profiles::{credential_profile_count, kernel_profile_count},
    registry_callback::{self, RegistryAction},
    token,
    token_control::{self, AdjustTokenAction, SystemTokenAction},
    wdigest::{self, WdigestAction},
};

use core::fmt::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    Arguments(ArgumentError),
    TrailingArguments,
    UnknownCommand,
}

impl CommandError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Arguments(error) => error.message(),
            Self::TrailingArguments => "unexpected trailing arguments",
            Self::UnknownCommand => "unknown command",
        }
    }
}

impl From<ArgumentError> for CommandError {
    fn from(error: ArgumentError) -> Self {
        Self::Arguments(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Minifilter arguments are owned because the BOF has no allocator and cannot
// retain references into the loader's argument buffer across dispatch.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    AdapterCheck,
    Callback(CallbackKind, CallbackAction),
    Credentials(CredentialAction),
    Dse(DseAction),
    EtwTi(EtwTiAction),
    Help,
    Minifilter(MinifilterAction),
    Object(ObjectKind, ObjectAction),
    Preflight,
    Process(ProcessSelector),
    Protection(ProtectionAction),
    Ppl(PplAction),
    Registry(RegistryAction),
    Status,
    Token(ProcessSelector),
    TokenAdjust(AdjustTokenAction),
    TokenSystem(SystemTokenAction),
    Wdigest(WdigestAction),
}

impl Command {
    pub fn parse(mut args: Arguments<'_>) -> Result<Self, CommandError> {
        if args.is_empty() {
            return Ok(Self::Help);
        }

        let command = match args.string()? {
            "adapter-check" => Self::AdapterCheck,
            "callback" => {
                let (kind, action) = parse_callback(&mut args)?;
                Self::Callback(kind, action)
            }
            "credentials" => Self::Credentials(parse_credentials(&mut args)?),
            "dse" => Self::Dse(parse_dse(&mut args)?),
            "etw-ti" => Self::EtwTi(parse_etw_ti(&mut args)?),
            "help" => Self::Help,
            "minifilter" => Self::Minifilter(parse_minifilter(&mut args)?),
            "object" => {
                let (kind, action) = parse_object(&mut args)?;
                Self::Object(kind, action)
            }
            "preflight" => Self::Preflight,
            "ppl" => Self::Ppl(parse_ppl(&mut args)?),
            "process" => parse_process(&mut args)?,
            "protection" => Self::Protection(parse_protection(&mut args)?),
            "registry" => Self::Registry(parse_registry(&mut args)?),
            "status" => Self::Status,
            "token" => parse_token(&mut args)?,
            "wdigest" => Self::Wdigest(parse_wdigest(&mut args)?),
            _ => return Err(CommandError::UnknownCommand),
        };

        if !args.is_empty() {
            return Err(CommandError::TrailingArguments);
        }

        Ok(command)
    }

    pub fn run<A: KernelAdapter>(self, adapter: &mut A, output: &mut Output) {
        match self {
            Self::AdapterCheck => print_adapter_check(adapter, output),
            Self::Callback(kind, action) => callback::run(adapter, kind, action, output),
            Self::Credentials(action) => credentials::run(adapter, action, output),
            Self::Dse(action) => dse::run(adapter, action, output),
            Self::EtwTi(action) => etw_ti::run(adapter, action, output),
            Self::Help => print_help(output),
            Self::Minifilter(action) => minifilter::run(action, output),
            Self::Object(kind, action) => object_callback::run(adapter, kind, action, output),
            Self::Preflight => print_preflight(output),
            Self::Ppl(action) => ppl::run(adapter, action, output),
            Self::Process(selector) => process::inspect(adapter, selector, output),
            Self::Protection(action) => process_control::run(adapter, action, output),
            Self::Registry(action) => registry_callback::run(adapter, action, output),
            Self::Status => print_status(adapter, output),
            Self::Token(selector) => token::inspect(adapter, selector, output),
            Self::TokenAdjust(action) => token_control::run_adjust(adapter, action, output),
            Self::TokenSystem(action) => token_control::run_system(adapter, action, output),
            Self::Wdigest(action) => wdigest::run(adapter, action, output),
        }
    }
}

pub fn print_usage(output: &mut Output) {
    output.line("[*] Usage: kernel <command> [arguments]");
}

fn print_help(output: &mut Output) {
    output.line("[*] Kernel BOF");
    output.line("[*] help           Show available commands");
    output.line("[*] minifilter list");
    output
        .line("[*] minifilter inspect <filter> <instance> <\\Device\\HarddiskVolumeN> <altitude>");
    output.line(
        "[*] minifilter <disable|cycle> <filter> <instance> <\\Device\\HarddiskVolumeN> <altitude>",
    );
    output.line("[*] minifilter restore");
    output.line("[*] preflight      Show Windows, VBS, HVCI, and Code Integrity state");
    output.line("[*] status         Show compiled adapter capabilities");
    output.line("[*] adapter-check  Prove the adapter and exact kernel profile read path");
    output.line("[*] callback <process|thread|image> list");
    output.line("[*] callback <process|thread|image> <disable|cycle> <module.sys> <rva>");
    output.line("[*] callback <process|thread|image> restore");
    output.line("[*] credentials read             Read VTL0 authentication material");
    output.line("[*] dse <state|cycle|restore> HVCI/VBS-off only for cycle");
    output.line("[*] etw-ti <state|cycle|disable|restore> Control ETW Threat Intelligence state");
    output.line("[*] object <process|thread> list");
    output.line(
        "[*] object <process|thread> <disable|cycle> <module.sys> <ops> <pre-rva> <post-rva>",
    );
    output.line("[*] object <process|thread> restore");
    output.line("[*] process self                Inspect the current host process");
    output.line("[*] process auth                Inspect the authentication service");
    output.line("[*] process inspect <pid>       Inspect one process by PID");
    output.line("[*] protection <self|auth|pid> cycle <expected-byte> <changed-byte>");
    output.line("[*] protection <self|auth|pid> restore");
    output.line("[*] ppl <cycle|disable|restore> Control authentication-service PPL state");
    output.line("[*] registry <list|cycle|disable|restore> Control the registry callback list");
    output.line("[*] token <self|auth|pid>       Inspect one process token and integrity level");
    output.line("[*] token system <cycle|restore> Perform or recover an atomic self-token swap");
    output.line("[*] token adjust <self|pid> <cycle|restore> Cycle privileges and integrity");
    output.line("[*] wdigest <state|cycle|enable|restore> Control future-logon retention");
    output.line("[+] No kernel state was changed");
}

fn parse_process(args: &mut Arguments<'_>) -> Result<Command, CommandError> {
    let action = args.string()?;

    if action == "inspect" {
        return Ok(Command::Process(ProcessSelector::Pid(
            parse_pid(args.string()?).ok_or(CommandError::UnknownCommand)?,
        )));
    }

    Ok(Command::Process(parse_selector_value(action)?))
}

fn parse_dse(args: &mut Arguments<'_>) -> Result<DseAction, CommandError> {
    match args.string()? {
        "state" => Ok(DseAction::State),
        "cycle" => Ok(DseAction::Cycle),
        "restore" => Ok(DseAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_credentials(args: &mut Arguments<'_>) -> Result<CredentialAction, CommandError> {
    match args.string()? {
        "read" => Ok(CredentialAction::Read),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_minifilter(args: &mut Arguments<'_>) -> Result<MinifilterAction, CommandError> {
    match args.string()? {
        "list" => Ok(MinifilterAction::List),
        "inspect" => Ok(MinifilterAction::Inspect(parse_minifilter_target(args)?)),
        "cycle" => Ok(MinifilterAction::Cycle(parse_minifilter_target(args)?)),
        "disable" => Ok(MinifilterAction::Disable(parse_minifilter_target(args)?)),
        "restore" => Ok(MinifilterAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_minifilter_target(args: &mut Arguments<'_>) -> Result<MinifilterTarget, CommandError> {
    let filter = args.string()?;
    let instance = args.string()?;
    let volume = args.string()?;
    let altitude = args.string()?;

    MinifilterTarget::new(filter, instance, volume, altitude).ok_or(CommandError::UnknownCommand)
}

fn parse_protection(args: &mut Arguments<'_>) -> Result<ProtectionAction, CommandError> {
    let selector = parse_selector(args)?;

    match args.string()? {
        "cycle" => {
            let expected = parse_u8(args.string()?).ok_or(CommandError::UnknownCommand)?;
            let changed = parse_u8(args.string()?).ok_or(CommandError::UnknownCommand)?;

            Ok(ProtectionAction::Cycle {
                selector,
                expected,
                changed,
            })
        }
        "restore" => Ok(ProtectionAction::Restore(selector)),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_callback(
    args: &mut Arguments<'_>,
) -> Result<(CallbackKind, CallbackAction), CommandError> {
    let kind = match args.string()? {
        "process" => CallbackKind::Process,
        "thread" => CallbackKind::Thread,
        "image" => CallbackKind::Image,
        _ => return Err(CommandError::UnknownCommand),
    };

    let action = match args.string()? {
        "list" => CallbackAction::List,
        "restore" => CallbackAction::Restore,
        "disable" => CallbackAction::Disable(parse_callback_target(args)?),
        "cycle" => CallbackAction::Cycle(parse_callback_target(args)?),
        _ => return Err(CommandError::UnknownCommand),
    };

    Ok((kind, action))
}

fn parse_callback_target(args: &mut Arguments<'_>) -> Result<TargetSpec, CommandError> {
    let name = args.string()?;
    let rva = parse_u32(args.string()?).ok_or(CommandError::UnknownCommand)?;

    TargetSpec::new(name, rva).ok_or(CommandError::UnknownCommand)
}

fn parse_object(args: &mut Arguments<'_>) -> Result<(ObjectKind, ObjectAction), CommandError> {
    let kind = match args.string()? {
        "process" => ObjectKind::Process,
        "thread" => ObjectKind::Thread,
        _ => return Err(CommandError::UnknownCommand),
    };
    let action = match args.string()? {
        "list" => ObjectAction::List,
        "restore" => ObjectAction::Restore,
        "disable" => ObjectAction::Disable(parse_object_target(args)?),
        "cycle" => ObjectAction::Cycle(parse_object_target(args)?),
        _ => return Err(CommandError::UnknownCommand),
    };

    Ok((kind, action))
}

fn parse_object_target(args: &mut Arguments<'_>) -> Result<ObjectTarget, CommandError> {
    let name = args.string()?;
    let operations = parse_u32(args.string()?).ok_or(CommandError::UnknownCommand)?;
    let pre_rva = parse_u32(args.string()?).ok_or(CommandError::UnknownCommand)?;
    let post_rva = parse_u32(args.string()?).ok_or(CommandError::UnknownCommand)?;

    ObjectTarget::new(name, operations, pre_rva, post_rva).ok_or(CommandError::UnknownCommand)
}

fn parse_ppl(args: &mut Arguments<'_>) -> Result<PplAction, CommandError> {
    match args.string()? {
        "cycle" => Ok(PplAction::Cycle),
        "disable" => Ok(PplAction::Disable),
        "restore" => Ok(PplAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_etw_ti(args: &mut Arguments<'_>) -> Result<EtwTiAction, CommandError> {
    match args.string()? {
        "state" => Ok(EtwTiAction::State),
        "cycle" => Ok(EtwTiAction::Cycle),
        "disable" => Ok(EtwTiAction::Disable),
        "restore" => Ok(EtwTiAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_registry(args: &mut Arguments<'_>) -> Result<RegistryAction, CommandError> {
    match args.string()? {
        "list" => Ok(RegistryAction::List),
        "cycle" => Ok(RegistryAction::Cycle),
        "disable" => Ok(RegistryAction::Disable),
        "restore" => Ok(RegistryAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_selector(args: &mut Arguments<'_>) -> Result<ProcessSelector, CommandError> {
    parse_selector_value(args.string()?)
}

fn parse_token(args: &mut Arguments<'_>) -> Result<Command, CommandError> {
    let action = args.string()?;

    if action == "system" {
        let operation = match args.string()? {
            "cycle" => SystemTokenAction::Cycle,
            "restore" => SystemTokenAction::Restore,
            _ => return Err(CommandError::UnknownCommand),
        };

        return Ok(Command::TokenSystem(operation));
    }

    if action == "adjust" {
        let selector = parse_selector(args)?;

        if matches!(selector, ProcessSelector::AuthenticationService) {
            return Err(CommandError::UnknownCommand);
        }

        let operation = match args.string()? {
            "cycle" => AdjustTokenAction::Cycle(selector),
            "restore" => AdjustTokenAction::Restore(selector),
            _ => return Err(CommandError::UnknownCommand),
        };

        return Ok(Command::TokenAdjust(operation));
    }

    Ok(Command::Token(parse_selector_value(action)?))
}

fn parse_wdigest(args: &mut Arguments<'_>) -> Result<WdigestAction, CommandError> {
    match args.string()? {
        "state" => Ok(WdigestAction::State),
        "cycle" => Ok(WdigestAction::Cycle),
        "enable" => Ok(WdigestAction::Enable),
        "restore" => Ok(WdigestAction::Restore),
        _ => Err(CommandError::UnknownCommand),
    }
}

fn parse_selector_value(value: &str) -> Result<ProcessSelector, CommandError> {
    match value {
        "auth" => Ok(ProcessSelector::AuthenticationService),
        "self" => Ok(ProcessSelector::Current),
        _ => parse_pid(value)
            .map(ProcessSelector::Pid)
            .ok_or(CommandError::UnknownCommand),
    }
}

fn parse_pid(value: &str) -> Option<u32> {
    let parsed = parse_u32(value)?;

    if parsed <= 4 {
        return None;
    }

    Some(parsed)
}

fn parse_u32(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let mut parsed = 0_u64;
    let (radix, digits) = if let Some(digits) = value.strip_prefix("0x") {
        (16_u64, digits)
    } else {
        (10_u64, value)
    };

    if digits.is_empty() {
        return None;
    }

    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            b'a'..=b'f' if radix == 16 => (byte - b'a' + 10) as u64,
            b'A'..=b'F' if radix == 16 => (byte - b'A' + 10) as u64,
            _ => return None,
        };
        parsed = parsed.checked_mul(radix)?.checked_add(digit)?;

        if parsed > u32::MAX as u64 {
            return None;
        }
    }

    Some(parsed as u32)
}

fn parse_u8(value: &str) -> Option<u8> {
    let value = parse_u32(value)?;

    u8::try_from(value).ok()
}

fn print_preflight(output: &mut Output) {
    output.line("[*] Checking Windows kernel protection state");

    let protection = match platform::query_host_protection() {
        Ok(protection) => protection,
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Preflight failed at {} (0x{:08x})",
                error.stage(),
                error.code()
            );
            return;
        }
    };

    let _ = writeln!(
        output,
        "[*] Windows         : {}.{}.{} x64",
        protection.major, protection.minor, protection.build
    );
    let _ = writeln!(
        output,
        "[*] Code Integrity  : kernel={} test-signing={} user-mode={} audit={}",
        enabled_disabled(protection.kernel_code_integrity_enabled()),
        enabled_disabled(protection.test_signing_enabled()),
        enabled_disabled(protection.user_mode_code_integrity_enabled()),
        enabled_disabled(protection.user_mode_code_integrity_audit())
    );
    let _ = writeln!(
        output,
        "[*] VBS and HVCI    : secure-kernel={} hvci={} trustlet={}",
        running_stopped(protection.secure_kernel_running()),
        enabled_disabled(protection.hvci_enabled()),
        running_stopped(protection.trustlet_running())
    );
    let _ = writeln!(
        output,
        "[*] DSE mutation    : {}",
        if protection.dse_mutation_supported() {
            "compatible"
        } else {
            "blocked by safety gate"
        }
    );
    output.line("[+] Preflight complete; no driver was opened and no state was changed");
}

fn print_status<A: KernelAdapter>(adapter: &mut A, output: &mut Output) {
    let info = adapter.info();

    output.line("[*] Checking the driver-agnostic adapter");
    let _ = writeln!(
        output,
        "[*] Profiles        : kernel={} credential={}",
        kernel_profile_count(),
        credential_profile_count()
    );
    output.field("Adapter", info.name);
    let _ = writeln!(
        output,
        "[*] Contract        : version={} capabilities=0x{:08x}",
        info.contract_version,
        info.capabilities.bits()
    );
    output.field(
        "Kernel read",
        yes_no(info.capabilities.contains(Capability::KernelRead)),
    );
    output.field(
        "Kernel write",
        yes_no(info.capabilities.contains(Capability::KernelWrite)),
    );
    output.field(
        "Physical read",
        yes_no(info.capabilities.contains(Capability::PhysicalRead)),
    );
    output.field(
        "Physical write",
        yes_no(info.capabilities.contains(Capability::PhysicalWrite)),
    );

    match adapter.open(info.capabilities) {
        Ok(()) => {
            output.line("[+] Adapter opened successfully");

            if adapter.close().is_err() {
                output.line("[-] Adapter close failed");
            }
        }
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Adapter open failed: {} (0x{:08x})",
                error.message(),
                error.code()
            );
        }
    }
}

fn print_adapter_check<A: KernelAdapter>(adapter: &mut A, output: &mut Output) {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

    output.line("[*] Checking adapter contract and exact kernel identity");
    let info = adapter.info();

    if let Err(error) = info.validate(REQUIRED, 8) {
        let _ = writeln!(output, "[-] Adapter contract rejected: {}", error.message());
        return;
    }

    if let Err(error) = adapter.open(REQUIRED) {
        let _ = writeln!(
            output,
            "[-] Adapter open failed: {} (0x{:08x})",
            error.message(),
            error.code()
        );
        return;
    }

    let result = check_adapter_read_path(adapter, output);
    let close = adapter.close();

    if let Err(error) = result {
        let _ = writeln!(output, "[-] Adapter check failed: {error}");
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
        output
            .line("[+] Adapter check complete; repeated kernel read matched and no state changed");
    }
}

fn check_adapter_read_path<A: KernelAdapter>(
    adapter: &mut A,
    output: &mut Output,
) -> Result<(), &'static str> {
    let modules = SystemModules::query().map_err(|error| {
        let _ = writeln!(
            output,
            "[-] Loaded-module query failed at {} (0x{:08x})",
            error.stage(),
            error.code()
        );
        error.stage()
    })?;
    let context = verify_loaded_kernel(adapter, &modules).map_err(|error| {
        let _ = writeln!(
            output,
            "[-] Kernel identity failed at {} (0x{:08x})",
            error.stage(),
            error.code()
        );
        error.stage()
    })?;

    let _ = writeln!(output, "[*] Loaded modules  : {}", modules.len());
    let _ = writeln!(
        output,
        "[*] Kernel profile  : {} exact PE and PDB match",
        context.profile.display_build
    );

    let mut first = [0_u8; KERNEL_HEADER_BYTES];
    let mut second = [0_u8; KERNEL_HEADER_BYTES];
    let first_result = adapter.read_kernel(context.base, &mut first);
    let second_result = adapter.read_kernel(context.base, &mut second);
    let matched = first_result.is_ok() && second_result.is_ok() && first == second;
    zero(&mut first);
    zero(&mut second);

    if !matched {
        return Err("repeat-kernel-read");
    }

    Ok(())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn enabled_disabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

const fn running_stopped(value: bool) -> &'static str {
    if value { "running" } else { "not running" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed(value: &[u8]) -> ([u8; 32], usize) {
        let mut buffer = [0_u8; 32];
        let item_length = value.len() + 1;
        let outer_length = ITEM_LENGTH_BYTES + item_length;

        buffer[..4].copy_from_slice(&(outer_length as u32).to_le_bytes());
        buffer[4..8].copy_from_slice(&(item_length as u32).to_le_bytes());
        buffer[8..8 + value.len()].copy_from_slice(value);

        (buffer, OUTER_LENGTH_BYTES + outer_length)
    }

    fn packed_items(values: &[&[u8]]) -> ([u8; 256], usize) {
        let mut buffer = [0_u8; 256];
        let mut offset = OUTER_LENGTH_BYTES;

        for value in values {
            let item_length = value.len() + 1;
            buffer[offset..offset + ITEM_LENGTH_BYTES]
                .copy_from_slice(&(item_length as u32).to_le_bytes());
            offset += ITEM_LENGTH_BYTES;
            buffer[offset..offset + value.len()].copy_from_slice(value);
            offset += item_length;
        }

        buffer[..OUTER_LENGTH_BYTES]
            .copy_from_slice(&((offset - OUTER_LENGTH_BYTES) as u32).to_le_bytes());

        (buffer, offset)
    }

    const OUTER_LENGTH_BYTES: usize = 4;
    const ITEM_LENGTH_BYTES: usize = 4;

    #[test]
    fn parses_status() {
        let (buffer, length) = packed(b"status");
        let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

        assert_eq!(Command::parse(args), Ok(Command::Status));
    }

    #[test]
    fn parses_preflight() {
        let (buffer, length) = packed(b"preflight");
        let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

        assert_eq!(Command::parse(args), Ok(Command::Preflight));
    }

    #[test]
    fn reports_unknown_command() {
        let (buffer, length) = packed(b"unknown");
        let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

        assert_eq!(Command::parse(args), Err(CommandError::UnknownCommand));
    }

    #[test]
    fn parses_process_pid() {
        let (buffer, length) = packed_items(&[b"process", b"inspect", b"4242"]);
        let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

        assert_eq!(
            Command::parse(args),
            Ok(Command::Process(ProcessSelector::Pid(4242)))
        );
    }

    #[test]
    fn rejects_system_pid() {
        let (buffer, length) = packed_items(&[b"process", b"inspect", b"4"]);
        let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

        assert_eq!(Command::parse(args), Err(CommandError::UnknownCommand));
    }

    #[test]
    fn parses_every_advertised_action() {
        let cases: &[&[&[u8]]] = &[
            &[b"help"],
            &[b"preflight"],
            &[b"status"],
            &[b"adapter-check"],
            &[b"process", b"self"],
            &[b"process", b"auth"],
            &[b"process", b"inspect", b"4242"],
            &[b"token", b"self"],
            &[b"token", b"auth"],
            &[b"token", b"4242"],
            &[b"token", b"system", b"cycle"],
            &[b"token", b"system", b"restore"],
            &[b"token", b"adjust", b"self", b"cycle"],
            &[b"token", b"adjust", b"self", b"restore"],
            &[b"token", b"adjust", b"4242", b"cycle"],
            &[b"token", b"adjust", b"4242", b"restore"],
            &[b"ppl", b"cycle"],
            &[b"ppl", b"disable"],
            &[b"ppl", b"restore"],
            &[b"protection", b"self", b"cycle", b"0x41", b"0"],
            &[b"protection", b"self", b"restore"],
            &[b"protection", b"auth", b"cycle", b"0x41", b"0"],
            &[b"protection", b"auth", b"restore"],
            &[b"protection", b"4242", b"cycle", b"0x41", b"0"],
            &[b"protection", b"4242", b"restore"],
            &[b"callback", b"process", b"list"],
            &[
                b"callback",
                b"process",
                b"disable",
                b"example.sys",
                b"0x1000",
            ],
            &[b"callback", b"process", b"cycle", b"example.sys", b"0x1000"],
            &[b"callback", b"process", b"restore"],
            &[b"callback", b"thread", b"list"],
            &[
                b"callback",
                b"thread",
                b"disable",
                b"example.sys",
                b"0x1000",
            ],
            &[b"callback", b"thread", b"cycle", b"example.sys", b"0x1000"],
            &[b"callback", b"thread", b"restore"],
            &[b"callback", b"image", b"list"],
            &[b"callback", b"image", b"disable", b"example.sys", b"0x1000"],
            &[b"callback", b"image", b"cycle", b"example.sys", b"0x1000"],
            &[b"callback", b"image", b"restore"],
            &[b"object", b"process", b"list"],
            &[
                b"object",
                b"process",
                b"disable",
                b"example.sys",
                b"3",
                b"0x1000",
                b"0x2000",
            ],
            &[
                b"object",
                b"process",
                b"cycle",
                b"example.sys",
                b"3",
                b"0x1000",
                b"0x2000",
            ],
            &[b"object", b"process", b"restore"],
            &[b"object", b"thread", b"list"],
            &[
                b"object",
                b"thread",
                b"disable",
                b"example.sys",
                b"3",
                b"0x1000",
                b"0x2000",
            ],
            &[
                b"object",
                b"thread",
                b"cycle",
                b"example.sys",
                b"3",
                b"0x1000",
                b"0x2000",
            ],
            &[b"object", b"thread", b"restore"],
            &[b"registry", b"list"],
            &[b"registry", b"cycle"],
            &[b"registry", b"disable"],
            &[b"registry", b"restore"],
            &[b"etw-ti", b"state"],
            &[b"etw-ti", b"cycle"],
            &[b"etw-ti", b"disable"],
            &[b"etw-ti", b"restore"],
            &[b"dse", b"state"],
            &[b"dse", b"cycle"],
            &[b"dse", b"restore"],
            &[b"wdigest", b"state"],
            &[b"wdigest", b"cycle"],
            &[b"wdigest", b"enable"],
            &[b"wdigest", b"restore"],
            &[b"credentials", b"read"],
            &[b"minifilter", b"list"],
            &[
                b"minifilter",
                b"inspect",
                b"ExampleFilter",
                b"ExampleInstance",
                b"\\Device\\HarddiskVolume3",
                b"12345",
            ],
            &[
                b"minifilter",
                b"cycle",
                b"ExampleFilter",
                b"ExampleInstance",
                b"\\Device\\HarddiskVolume3",
                b"12345",
            ],
            &[
                b"minifilter",
                b"disable",
                b"ExampleFilter",
                b"ExampleInstance",
                b"\\Device\\HarddiskVolume3",
                b"12345",
            ],
            &[b"minifilter", b"restore"],
        ];

        for values in cases {
            let (buffer, length) = packed_items(values);
            let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

            assert!(Command::parse(args).is_ok());
        }
    }

    #[test]
    fn rejects_numeric_credential_output_levels() {
        for level in [b"1".as_slice(), b"2".as_slice(), b"3".as_slice()] {
            let (buffer, length) = packed_items(&[b"credentials", b"read", level]);
            let args = Arguments::new(buffer.as_ptr(), length as i32).unwrap();

            assert_eq!(Command::parse(args), Err(CommandError::TrailingArguments));
        }
    }
}
