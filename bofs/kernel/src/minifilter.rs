//! File-system minifilter inventory and reversible instance control.

use crate::{
    bytes::{read_u16, read_u32, write_u32, write_u64, zero},
    output::Output,
    recovery::{RecoveryError, RecoveryStore, checksum},
};
use core::{fmt::Write, ptr::NonNull, slice};

#[cfg(not(test))]
use core::ffi::c_void;

const FILTER_FULL_INFORMATION: u32 = 0;
const FILTER_INSTANCE_FULL_INFORMATION: u32 = 2;
const FILTER_BUFFER_BYTES: usize = 64 * 1024;
const FILTER_NAME_OFFSET: usize = 14;
const MAX_FILTERS: usize = 256;
const MAX_INSTANCE_ENTRIES: usize = 4096;
const MAX_BATCHES: usize = 64;
const MAX_FIELD_CHARS: usize = 260;
const HR_NO_MORE_ITEMS: i32 = 0x8007_0103_u32 as i32;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const INVALID_HANDLE_VALUE: isize = -1;
const JOURNAL_BYTES: usize = 2144;
const JOURNAL_MAGIC: u32 = 0x544c_464b;
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NONCE: u64 = 0x3154_4c46_4e52_4b00;
const RECOVERY_NAME: &[u16] = &[99, 97, 99, 104, 101, 50, 68, 52, 67, 46, 116, 109, 112, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinifilterAction {
    List,
    Inspect(MinifilterTarget),
    Cycle(MinifilterTarget),
    Disable(MinifilterTarget),
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinifilterTarget {
    filter: WideField,
    instance: WideField,
    volume: WideField,
    altitude: WideField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WideField {
    length: u16,
    value: [u16; MAX_FIELD_CHARS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MinifilterJournal {
    target: MinifilterTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Inventory {
    count: usize,
    fingerprint: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MinifilterError {
    stage: &'static str,
    code: u32,
    recovery_retained: bool,
}

struct Buffer {
    address: NonNull<u8>,
}

pub fn run(action: MinifilterAction, output: &mut Output) {
    let result = match action {
        MinifilterAction::List => list(output),
        MinifilterAction::Inspect(target) => inspect(target, output),
        MinifilterAction::Cycle(target) | MinifilterAction::Disable(target) => {
            change(action, target, output)
        }
        MinifilterAction::Restore => restore(output),
    };

    match result {
        Ok(()) => output.line(match action {
            MinifilterAction::List => "[+] Minifilter inventory complete; no changes made",
            MinifilterAction::Inspect(_) => {
                "[+] Exact minifilter instance inspected; no changes made"
            }
            MinifilterAction::Cycle(_) => {
                "[+] Minifilter instance cycle complete; original attachment restored"
            }
            MinifilterAction::Disable(_) => {
                "[+] Minifilter instance detached; run `minifilter restore` when finished"
            }
            MinifilterAction::Restore => {
                "[+] Minifilter instance restored; recovery record removed"
            }
        }),
        Err(error) => {
            let _ = writeln!(
                output,
                "[-] Minifilter action failed at {} (0x{:08x}); recovery-retained={}",
                error.stage,
                error.code,
                yes_no(error.recovery_retained)
            );
        }
    }
}

fn list(output: &mut Output) -> Result<(), MinifilterError> {
    output.line("[*] Enumerating registered file-system minifilters");
    let mut buffer = Buffer::new()?;
    let first = enumerate_filters(buffer.as_mut(), true, output)?;
    let second = enumerate_filters(buffer.as_mut(), false, output)?;

    if first != second {
        return Err(filter_error("minifilter-inventory-stability", 1237));
    }

    let _ = writeln!(
        output,
        "[*] Registered      : {} stable entries",
        first.count
    );

    Ok(())
}

fn inspect(target: MinifilterTarget, output: &mut Output) -> Result<(), MinifilterError> {
    output.line("[*] Inspecting one exact minifilter instance");
    let mut buffer = Buffer::new()?;
    let first = find_target_instances(buffer.as_mut(), target, true, output)?;
    let second = find_target_instances(buffer.as_mut(), target, false, output)?;

    if first != 1 || second != 1 {
        return Err(filter_error("minifilter-exact-target", 1168));
    }

    Ok(())
}

fn change(
    action: MinifilterAction,
    target: MinifilterTarget,
    output: &mut Output,
) -> Result<(), MinifilterError> {
    output.line(match action {
        MinifilterAction::Cycle(_) => "[*] Cycling one exact minifilter instance",
        _ => "[*] Detaching one exact minifilter instance",
    });
    let mut buffer = Buffer::new()?;
    let first = find_target_instances(buffer.as_mut(), target, false, output)?;
    let second = find_target_instances(buffer.as_mut(), target, false, output)?;

    if first != 1 || second != 1 {
        return Err(filter_error("minifilter-exact-precheck", 1168));
    }

    let journal = MinifilterJournal { target };
    let mut record = journal.encode();
    RecoveryStore::write_new(RECOVERY_NAME, &record)
        .map_err(|error| recovery_error(error, false))?;
    let detached = match filter_detach(target) {
        Ok(detached) => detached,
        Err(error) => {
            let restored = match find_target_instances(buffer.as_mut(), target, false, output) {
                Ok(1) => true,
                Ok(0) => {
                    filter_attach(target)
                        && find_target_instances(buffer.as_mut(), target, false, output).ok()
                            == Some(1)
                }
                _ => false,
            };
            let recovery_removed = restored && RecoveryStore::delete(RECOVERY_NAME).is_ok();
            zero(&mut record);

            return Err(MinifilterError {
                stage: error.stage,
                code: error.code,
                recovery_retained: !recovery_removed,
            });
        }
    };

    if !detached || find_target_instances(buffer.as_mut(), target, false, output)? != 0 {
        let rollback = filter_attach(target)
            && find_target_instances(buffer.as_mut(), target, false, output).ok() == Some(1);

        if rollback {
            let _ = RecoveryStore::delete(RECOVERY_NAME);
        }

        zero(&mut record);
        return Err(MinifilterError {
            stage: "minifilter-detach-readback",
            code: 13,
            recovery_retained: !rollback,
        });
    }

    output.line("[*] Exact instance detached and absence verified");

    if matches!(action, MinifilterAction::Cycle(_)) {
        if !filter_attach(target)
            || find_target_instances(buffer.as_mut(), target, false, output)? != 1
        {
            zero(&mut record);
            return Err(retained_error("minifilter-cycle-attach", 13));
        }

        RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true))?;
        output.line("[*] Exact instance reattached and identity verified");
    }

    zero(&mut record);

    Ok(())
}

fn restore(output: &mut Output) -> Result<(), MinifilterError> {
    output.line("[*] Restoring an interrupted minifilter action");
    let mut record = [0_u8; JOURNAL_BYTES];
    RecoveryStore::read_exact(RECOVERY_NAME, &mut record)
        .map_err(|error| recovery_error(error, true))?;
    let journal = MinifilterJournal::decode(&record)
        .ok_or_else(|| retained_error("minifilter-recovery-integrity", 13))?;
    zero(&mut record);
    let mut buffer = Buffer::new()?;
    let current = find_target_instances(buffer.as_mut(), journal.target, false, output)?;

    if current == 0 {
        if !filter_attach(journal.target)
            || find_target_instances(buffer.as_mut(), journal.target, false, output)? != 1
        {
            return Err(retained_error("minifilter-recovery-attach", 13));
        }
    } else if current != 1 {
        return Err(retained_error("minifilter-recovery-state", 13));
    }

    RecoveryStore::delete(RECOVERY_NAME).map_err(|error| recovery_error(error, true))?;
    output.line("[*] Exact instance attachment verified");

    Ok(())
}

fn enumerate_filters(
    buffer: &mut [u8],
    emit: bool,
    output: &mut Output,
) -> Result<Inventory, MinifilterError> {
    zero(buffer);
    let mut returned = 0_u32;
    let mut find = INVALID_HANDLE_VALUE;
    let first = filter_find_first(buffer, &mut returned, &mut find);

    if first == HR_NO_MORE_ITEMS {
        return Ok(Inventory {
            count: 0,
            fingerprint: checksum(&[]),
        });
    }

    if first < 0 || find == INVALID_HANDLE_VALUE || !valid_returned(returned) {
        return Err(filter_error("minifilter-find-first", first as u32));
    }

    let mut result = Inventory {
        count: 0,
        fingerprint: 0xcbf2_9ce4_8422_2325,
    };
    let mut final_error = None;

    loop {
        if let Err(error) =
            parse_filter_batch(&buffer[..returned as usize], emit, output, &mut result)
        {
            final_error = Some(error);
            break;
        }

        zero(buffer);
        returned = 0;
        let next = filter_find_next(find, buffer, &mut returned);

        if next == HR_NO_MORE_ITEMS {
            break;
        }

        if next < 0 || !valid_returned(returned) {
            final_error = Some(filter_error("minifilter-find-next", next as u32));
            break;
        }
    }

    let close = filter_find_close(find);

    if close < 0 {
        return Err(filter_error("minifilter-find-close", close as u32));
    }

    if let Some(error) = final_error {
        return Err(error);
    }

    Ok(result)
}

fn parse_filter_batch(
    buffer: &[u8],
    emit: bool,
    output: &mut Output,
    result: &mut Inventory,
) -> Result<(), MinifilterError> {
    let mut offset = 0;

    while offset < buffer.len() {
        let remaining = buffer
            .get(offset..)
            .ok_or_else(|| filter_error("minifilter-batch-offset", 13))?;

        if remaining.len() < FILTER_NAME_OFFSET || result.count >= MAX_FILTERS {
            return Err(filter_error("minifilter-batch-boundary", 13));
        }

        let next = read_u32(remaining, 0).ok_or_else(|| filter_error("minifilter-next", 13))?;
        let frame = read_u32(remaining, 4).ok_or_else(|| filter_error("minifilter-frame", 13))?;
        let instances =
            read_u32(remaining, 8).ok_or_else(|| filter_error("minifilter-instances", 13))?;
        let name_bytes =
            read_u16(remaining, 12).ok_or_else(|| filter_error("minifilter-name", 13))? as usize;

        if name_bytes & 1 != 0
            || name_bytes > remaining.len() - FILTER_NAME_OFFSET
            || (next != 0 && (next as usize) < FILTER_NAME_OFFSET
                || next != 0 && next as usize & 7 != 0
                || next as usize > remaining.len())
        {
            return Err(filter_error("minifilter-entry-layout", 13));
        }

        let name = &remaining[FILTER_NAME_OFFSET..FILTER_NAME_OFFSET + name_bytes];
        result.fingerprint = mix_bytes(result.fingerprint, name);
        result.fingerprint = mix_u32(result.fingerprint, frame);
        result.fingerprint = mix_u32(result.fingerprint, instances);

        if emit {
            let mut printable = [0_u8; MAX_FIELD_CHARS];
            let text = printable_wide(name, &mut printable);
            let _ = writeln!(
                output,
                "[*] Filter {:>3}      : {} frame={} instances={}",
                result.count, text, frame, instances
            );
        }

        result.count += 1;

        if next == 0 {
            break;
        }

        offset = offset
            .checked_add(next as usize)
            .ok_or_else(|| filter_error("minifilter-next-overflow", 534))?;
    }

    Ok(())
}

fn find_target_instances(
    buffer: &mut [u8],
    target: MinifilterTarget,
    emit: bool,
    output: &mut Output,
) -> Result<usize, MinifilterError> {
    zero(buffer);
    let mut returned = 0_u32;
    let mut find = INVALID_HANDLE_VALUE;
    let first = instance_find_first(target.volume.as_ptr(), buffer, &mut returned, &mut find);

    if first == HR_NO_MORE_ITEMS {
        return Ok(0);
    }

    if first < 0 || find == INVALID_HANDLE_VALUE || !valid_returned(returned) {
        return Err(filter_error("minifilter-instance-first", first as u32));
    }

    let mut exact = 0;
    let mut entries = 0;
    let mut batches = 0;
    let mut final_error = None;

    loop {
        batches += 1;

        if batches > MAX_BATCHES {
            final_error = Some(filter_error("minifilter-instance-batches", 234));
            break;
        }

        if let Err(error) = parse_instance_batch(
            &buffer[..returned as usize],
            target,
            emit,
            output,
            &mut exact,
            &mut entries,
        ) {
            final_error = Some(error);
            break;
        }

        zero(buffer);
        returned = 0;
        let next = instance_find_next(find, buffer, &mut returned);

        if next == HR_NO_MORE_ITEMS {
            break;
        }

        if next < 0 || !valid_returned(returned) {
            final_error = Some(filter_error("minifilter-instance-next", next as u32));
            break;
        }
    }

    let close = instance_find_close(find);

    if close < 0 {
        return Err(filter_error("minifilter-instance-close", close as u32));
    }

    if let Some(error) = final_error {
        return Err(error);
    }

    if exact > 1 {
        return Err(filter_error("minifilter-target-not-unique", 13));
    }

    Ok(exact)
}

#[allow(clippy::too_many_arguments)]
fn parse_instance_batch(
    buffer: &[u8],
    target: MinifilterTarget,
    emit: bool,
    output: &mut Output,
    exact: &mut usize,
    entries: &mut usize,
) -> Result<(), MinifilterError> {
    let mut offset = 0;

    while offset < buffer.len() {
        *entries += 1;

        if *entries > MAX_INSTANCE_ENTRIES {
            return Err(filter_error("minifilter-instance-limit", 234));
        }

        let remaining = buffer
            .get(offset..)
            .ok_or_else(|| filter_error("minifilter-instance-offset", 13))?;

        if remaining.len() < 20 {
            return Err(filter_error("minifilter-instance-boundary", 13));
        }

        let next = read_u32(remaining, 0).unwrap_or(0) as usize;
        let span = if next == 0 { remaining.len() } else { next };

        if span < 20 || span > remaining.len() || (next != 0 && next & 7 != 0) {
            return Err(filter_error("minifilter-instance-layout", 13));
        }

        let entry = &remaining[..span];
        let instance = wide_field(entry, 4, 6)?;
        let altitude = wide_field(entry, 8, 10)?;
        let volume = wide_field(entry, 12, 14)?;
        let filter = wide_field(entry, 16, 18)?;
        let filter_match = target.filter.matches(filter);
        let selected = filter_match
            && target.instance.matches(instance)
            && target.altitude.matches(altitude)
            && target.volume.matches(volume);

        if selected {
            *exact += 1;
        }

        if emit && filter_match {
            let mut instance_text = [0_u8; MAX_FIELD_CHARS];
            let mut altitude_text = [0_u8; MAX_FIELD_CHARS];
            let mut volume_text = [0_u8; MAX_FIELD_CHARS];
            let instance = printable_wide(instance, &mut instance_text);
            let altitude = printable_wide(altitude, &mut altitude_text);
            let volume = printable_wide(volume, &mut volume_text);
            let _ = writeln!(
                output,
                "[*] Instance        : {} altitude={} volume={} selected={}",
                instance,
                altitude,
                volume,
                yes_no(selected)
            );
        }

        if next == 0 {
            break;
        }

        offset = offset
            .checked_add(next)
            .ok_or_else(|| filter_error("minifilter-instance-overflow", 534))?;
    }

    Ok(())
}

fn wide_field(
    buffer: &[u8],
    length_offset: usize,
    value_offset: usize,
) -> Result<&[u8], MinifilterError> {
    let length = read_u16(buffer, length_offset)
        .ok_or_else(|| filter_error("minifilter-field-length", 13))? as usize;
    let offset = read_u16(buffer, value_offset)
        .ok_or_else(|| filter_error("minifilter-field-offset", 13))? as usize;

    if length & 1 != 0
        || length / 2 >= MAX_FIELD_CHARS
        || offset > buffer.len()
        || length > buffer.len() - offset
    {
        return Err(filter_error("minifilter-field-layout", 13));
    }

    Ok(&buffer[offset..offset + length])
}

fn filter_detach(target: MinifilterTarget) -> Result<bool, MinifilterError> {
    let status = call_filter_detach(
        target.filter.as_ptr(),
        target.volume.as_ptr(),
        target.instance.as_ptr(),
    );

    if status < 0 {
        return Err(filter_error("minifilter-detach", status as u32));
    }

    Ok(true)
}

fn filter_attach(target: MinifilterTarget) -> bool {
    let mut created = [0_u16; MAX_FIELD_CHARS];
    let status = call_filter_attach(
        target.filter.as_ptr(),
        target.volume.as_ptr(),
        target.instance.as_ptr(),
        created.len() as u32,
        created.as_mut_ptr(),
    );
    zero_wide(&mut created);

    status >= 0
}

impl MinifilterTarget {
    pub fn new(filter: &str, instance: &str, volume: &str, altitude: &str) -> Option<Self> {
        Some(Self {
            filter: WideField::new(filter, false)?,
            instance: WideField::new(instance, false)?,
            volume: WideField::new(volume, true)?,
            altitude: WideField::new(altitude, false)?,
        })
    }

    fn valid(self) -> bool {
        self.filter.valid(false)
            && self.instance.valid(false)
            && self.volume.valid(true)
            && self.altitude.valid(false)
    }
}

impl WideField {
    fn new(input: &str, allow_backslash: bool) -> Option<Self> {
        if input.is_empty() || input.len() >= MAX_FIELD_CHARS {
            return None;
        }

        let mut result = Self {
            length: input.len() as u16,
            value: [0; MAX_FIELD_CHARS],
        };

        for (index, byte) in input.bytes().enumerate() {
            if !(0x20..=0x7e).contains(&byte)
                || matches!(byte, b'"' | b'\'' | b'`' | b';' | b'|' | b'&')
                || (!allow_backslash && matches!(byte, b'\\' | b'/'))
            {
                return None;
            }

            result.value[index] = byte as u16;
        }

        Some(result)
    }

    fn valid(self, allow_backslash: bool) -> bool {
        let length = self.length as usize;

        if length == 0 || length >= MAX_FIELD_CHARS || self.value[length] != 0 {
            return false;
        }

        for character in &self.value[..length] {
            let byte = *character as u8;

            if *character > 0x7e
                || !(0x20..=0x7e).contains(&byte)
                || matches!(byte, b'"' | b'\'' | b'`' | b';' | b'|' | b'&')
                || (!allow_backslash && matches!(byte, b'\\' | b'/'))
            {
                return false;
            }
        }

        self.value[length + 1..]
            .iter()
            .all(|character| *character == 0)
    }

    fn as_ptr(&self) -> *const u16 {
        self.value.as_ptr()
    }

    fn matches(self, input: &[u8]) -> bool {
        if input.len() != self.length as usize * 2 {
            return false;
        }

        for (index, expected) in self.value[..self.length as usize].iter().enumerate() {
            let Some(actual) = read_u16(input, index * 2) else {
                return false;
            };

            if fold_wide(actual) != fold_wide(*expected) {
                return false;
            }
        }

        true
    }
}

impl MinifilterJournal {
    fn encode(self) -> [u8; JOURNAL_BYTES] {
        let mut output = [0_u8; JOURNAL_BYTES];
        write_u32(&mut output, 0, JOURNAL_MAGIC);
        write_u32(&mut output, 4, JOURNAL_VERSION);
        write_u32(&mut output, 8, JOURNAL_BYTES as u32);
        encode_target(&self.target, &mut output[16..2112]);
        write_u64(&mut output, 2128, JOURNAL_NONCE);
        let integrity = checksum(&output[..2136]);
        write_u64(&mut output, 2136, integrity);

        output
    }

    fn decode(input: &[u8; JOURNAL_BYTES]) -> Option<Self> {
        if read_u32(input, 0)? != JOURNAL_MAGIC
            || read_u32(input, 4)? != JOURNAL_VERSION
            || read_u32(input, 8)? != JOURNAL_BYTES as u32
            || read_u64_local(input, 2128)? != JOURNAL_NONCE
            || read_u64_local(input, 2136)? != checksum(&input[..2136])
        {
            return None;
        }

        let target = decode_target(&input[16..2112])?;

        target.valid().then_some(Self { target })
    }
}

impl Buffer {
    fn new() -> Result<Self, MinifilterError> {
        let address = allocate_buffer();
        let Some(address) = NonNull::new(address) else {
            return Err(filter_error("minifilter-buffer-allocation", 8));
        };

        Ok(Self { address })
    }

    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.address.as_ptr(), FILTER_BUFFER_BYTES) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let buffer = self.as_mut();
        zero(buffer);
        let _ = free_buffer(self.address.as_ptr());
    }
}

fn encode_target(target: &MinifilterTarget, output: &mut [u8]) {
    let (chunks, _) = output.as_chunks_mut::<524>();

    for (field, chunk) in [
        target.filter,
        target.instance,
        target.volume,
        target.altitude,
    ]
    .iter()
    .zip(chunks)
    {
        chunk[..2].copy_from_slice(&field.length.to_le_bytes());

        for (index, character) in field.value.iter().enumerate() {
            let offset = 4 + index * 2;
            chunk[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
        }
    }
}

fn decode_target(input: &[u8]) -> Option<MinifilterTarget> {
    if input.len() != 2096 {
        return None;
    }

    let mut fields = [WideField {
        length: 0,
        value: [0; MAX_FIELD_CHARS],
    }; 4];
    let (chunks, _) = input.as_chunks::<524>();

    for (field, chunk) in fields.iter_mut().zip(chunks) {
        field.length = read_u16(chunk, 0)?;

        for (index, character) in field.value.iter_mut().enumerate() {
            *character = read_u16(chunk, 4 + index * 2)?;
        }
    }

    Some(MinifilterTarget {
        filter: fields[0],
        instance: fields[1],
        volume: fields[2],
        altitude: fields[3],
    })
}

fn printable_wide<'a>(input: &[u8], output: &'a mut [u8]) -> &'a str {
    let chars = core::cmp::min(input.len() / 2, output.len().saturating_sub(1));

    for (index, target) in output[..chars].iter_mut().enumerate() {
        let character = read_u16(input, index * 2).unwrap_or(b'?' as u16);
        *target = if (0x20..=0x7e).contains(&character) {
            character as u8
        } else {
            b'?'
        };
    }

    core::str::from_utf8(&output[..chars]).unwrap_or("?")
}

const fn fold_wide(value: u16) -> u16 {
    if value >= b'A' as u16 && value <= b'Z' as u16 {
        value + (b'a' - b'A') as u16
    } else {
        value
    }
}

fn mix_bytes(mut value: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        value ^= *byte as u64;
        value = value.wrapping_mul(0x1000_0000_01b3);
    }

    value
}

fn mix_u32(value: u64, number: u32) -> u64 {
    mix_bytes(value, &number.to_le_bytes())
}

fn read_u64_local(input: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = input.get(offset..offset + 8)?.try_into().ok()?;

    Some(u64::from_le_bytes(bytes))
}

fn valid_returned(returned: u32) -> bool {
    returned != 0 && returned as usize <= FILTER_BUFFER_BYTES
}

fn zero_wide(value: &mut [u16]) {
    for character in value {
        unsafe { core::ptr::write_volatile(character, 0) };
    }
}

const fn filter_error(stage: &'static str, code: u32) -> MinifilterError {
    MinifilterError {
        stage,
        code,
        recovery_retained: false,
    }
}

const fn retained_error(stage: &'static str, code: u32) -> MinifilterError {
    MinifilterError {
        stage,
        code,
        recovery_retained: true,
    }
}

const fn recovery_error(error: RecoveryError, recovery_retained: bool) -> MinifilterError {
    MinifilterError {
        stage: error.stage(),
        code: error.code(),
        recovery_retained,
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "VirtualAlloc"]
    fn virtual_alloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> *mut c_void;
    #[link_name = "VirtualFree"]
    fn virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32;
    #[link_name = "FilterFindFirst"]
    fn filter_find_first_raw(
        information_class: u32,
        buffer: *mut c_void,
        size: u32,
        returned: *mut u32,
        find: *mut isize,
    ) -> i32;
    #[link_name = "FilterFindNext"]
    fn filter_find_next_raw(
        find: isize,
        information_class: u32,
        buffer: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    #[link_name = "FilterFindClose"]
    fn filter_find_close_raw(find: isize) -> i32;
    #[link_name = "FilterVolumeInstanceFindFirst"]
    fn instance_find_first_raw(
        volume: *const u16,
        information_class: u32,
        buffer: *mut c_void,
        size: u32,
        returned: *mut u32,
        find: *mut isize,
    ) -> i32;
    #[link_name = "FilterVolumeInstanceFindNext"]
    fn instance_find_next_raw(
        find: isize,
        information_class: u32,
        buffer: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    #[link_name = "FilterVolumeInstanceFindClose"]
    fn instance_find_close_raw(find: isize) -> i32;
    #[link_name = "FilterDetach"]
    fn filter_detach_raw(filter: *const u16, volume: *const u16, instance: *const u16) -> i32;
    #[link_name = "FilterAttach"]
    fn filter_attach_raw(
        filter: *const u16,
        volume: *const u16,
        instance: *const u16,
        output_length: u32,
        output: *mut u16,
    ) -> i32;
}

#[cfg(not(test))]
fn allocate_buffer() -> *mut u8 {
    unsafe {
        virtual_alloc(
            core::ptr::null_mut(),
            FILTER_BUFFER_BYTES,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .cast()
    }
}

#[cfg(test)]
fn allocate_buffer() -> *mut u8 {
    NonNull::<u8>::dangling().as_ptr()
}

#[cfg(not(test))]
fn free_buffer(address: *mut u8) -> bool {
    unsafe { virtual_free(address.cast(), 0, MEM_RELEASE) != 0 }
}

#[cfg(test)]
fn free_buffer(_address: *mut u8) -> bool {
    true
}

#[cfg(not(test))]
fn filter_find_first(buffer: &mut [u8], returned: &mut u32, find: &mut isize) -> i32 {
    unsafe {
        filter_find_first_raw(
            FILTER_FULL_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            returned,
            find,
        )
    }
}

#[cfg(test)]
fn filter_find_first(_buffer: &mut [u8], _returned: &mut u32, _find: &mut isize) -> i32 {
    HR_NO_MORE_ITEMS
}

#[cfg(not(test))]
fn filter_find_next(find: isize, buffer: &mut [u8], returned: &mut u32) -> i32 {
    unsafe {
        filter_find_next_raw(
            find,
            FILTER_FULL_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            returned,
        )
    }
}

#[cfg(test)]
fn filter_find_next(_find: isize, _buffer: &mut [u8], _returned: &mut u32) -> i32 {
    HR_NO_MORE_ITEMS
}

#[cfg(not(test))]
fn filter_find_close(find: isize) -> i32 {
    unsafe { filter_find_close_raw(find) }
}

#[cfg(test)]
fn filter_find_close(_find: isize) -> i32 {
    0
}

#[cfg(not(test))]
fn instance_find_first(
    volume: *const u16,
    buffer: &mut [u8],
    returned: &mut u32,
    find: &mut isize,
) -> i32 {
    unsafe {
        instance_find_first_raw(
            volume,
            FILTER_INSTANCE_FULL_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            returned,
            find,
        )
    }
}

#[cfg(test)]
fn instance_find_first(
    _volume: *const u16,
    _buffer: &mut [u8],
    _returned: &mut u32,
    _find: &mut isize,
) -> i32 {
    HR_NO_MORE_ITEMS
}

#[cfg(not(test))]
fn instance_find_next(find: isize, buffer: &mut [u8], returned: &mut u32) -> i32 {
    unsafe {
        instance_find_next_raw(
            find,
            FILTER_INSTANCE_FULL_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            returned,
        )
    }
}

#[cfg(test)]
fn instance_find_next(_find: isize, _buffer: &mut [u8], _returned: &mut u32) -> i32 {
    HR_NO_MORE_ITEMS
}

#[cfg(not(test))]
fn instance_find_close(find: isize) -> i32 {
    unsafe { instance_find_close_raw(find) }
}

#[cfg(test)]
fn instance_find_close(_find: isize) -> i32 {
    0
}

#[cfg(not(test))]
fn call_filter_detach(filter: *const u16, volume: *const u16, instance: *const u16) -> i32 {
    unsafe { filter_detach_raw(filter, volume, instance) }
}

#[cfg(test)]
fn call_filter_detach(_filter: *const u16, _volume: *const u16, _instance: *const u16) -> i32 {
    0
}

#[cfg(not(test))]
fn call_filter_attach(
    filter: *const u16,
    volume: *const u16,
    instance: *const u16,
    output_length: u32,
    output: *mut u16,
) -> i32 {
    unsafe { filter_attach_raw(filter, volume, instance, output_length, output) }
}

#[cfg(test)]
fn call_filter_attach(
    _filter: *const u16,
    _volume: *const u16,
    _instance: *const u16,
    _output_length: u32,
    _output: *mut u16,
) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_round_trip_is_exact() {
        let target = MinifilterTarget::new(
            "ExampleFilter",
            "Example Instance",
            "\\Device\\HarddiskVolume3",
            "385201",
        )
        .unwrap();
        let journal = MinifilterJournal { target };

        assert_eq!(MinifilterJournal::decode(&journal.encode()), Some(journal));
    }

    #[test]
    fn target_rejects_shell_metacharacters() {
        assert!(MinifilterTarget::new("Filter;cmd", "Instance", "Volume", "1").is_none());
    }

    #[test]
    fn journal_rejects_tampering() {
        let target = MinifilterTarget::new("Filter", "Instance", "Volume", "1").unwrap();
        let mut record = MinifilterJournal { target }.encode();
        record[600] ^= 1;

        assert_eq!(MinifilterJournal::decode(&record), None);
    }
}
