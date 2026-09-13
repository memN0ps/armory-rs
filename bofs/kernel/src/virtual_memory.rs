//! Handleless process virtual memory through a Superfetch PFN snapshot.

use crate::{
    adapter::{AdapterError, KernelAdapter},
    bytes::zero,
    heap::HeapBuffer,
};
use core::{ffi::c_void, mem::size_of, ptr, slice};

const PAGE_BYTES: usize = 4096;
const SYSTEM_SUPERFETCH_INFORMATION: u32 = 79;
const SUPERFETCH_VERSION: u32 = 0x2d;
const SUPERFETCH_MAGIC: u32 = 0x6b75_6843;
const SUPERFETCH_PFN_QUERY: u32 = 6;
const SUPERFETCH_PRIVATE_SOURCE_QUERY: u32 = 8;
const SUPERFETCH_MEMORY_RANGES_QUERY: u32 = 17;
const SE_PROFILE_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xc000_0023_u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc000_0004_u32 as i32;
const PROCESS_PRIVATE: u64 = 0;
const ACTIVE_AND_VALID: u64 = 6;
const PROCESS_KEY_MASK: u64 = 0x0000_ffff_ffff_ffff;
const MAX_QUERY_BYTES: usize = 128 * 1024 * 1024;
const MAX_RANGE_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RANGES: usize = 4096;
const MAX_PHYSICAL_PAGES: usize = 0x0040_0000;
const MAX_TARGET_PAGES: usize = 0x0002_0000;
const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_PHYSICAL_READS: usize = 0x0004_0000;
const MAX_PHYSICAL_WRITES: usize = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualMemoryError {
    InvalidProcess,
    InvalidVirtualAddress,
    InvalidLength,
    Privilege(i32),
    PrivilegeRestore(i32),
    RangeProbe(i32),
    RangeQuery(i32),
    PrivateSourceProbe(i32),
    PrivateSourceQuery(i32),
    PfnQuery(i32),
    InvalidResponse,
    Allocation,
    ProcessNotFound,
    NotPresent,
    Physical(AdapterError),
    AddressOverflow,
    BudgetExceeded,
}

impl VirtualMemoryError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::InvalidProcess => "virtual-memory-process",
            Self::InvalidVirtualAddress => "virtual-memory-address",
            Self::InvalidLength => "virtual-memory-length",
            Self::Privilege(_) => "virtual-memory-profile-privilege",
            Self::PrivilegeRestore(_) => "virtual-memory-privilege-restore",
            Self::RangeProbe(_) => "virtual-memory-range-probe",
            Self::RangeQuery(_) => "virtual-memory-range-query",
            Self::PrivateSourceProbe(_) => "virtual-memory-process-probe",
            Self::PrivateSourceQuery(_) => "virtual-memory-process-query",
            Self::PfnQuery(_) => "virtual-memory-pfn-query",
            Self::InvalidResponse => "virtual-memory-system-response",
            Self::Allocation => "virtual-memory-allocation",
            Self::ProcessNotFound => "virtual-memory-process-not-found",
            Self::NotPresent => "virtual-memory-page-not-present",
            Self::Physical(_) => "virtual-memory-physical-io",
            Self::AddressOverflow => "virtual-memory-overflow",
            Self::BudgetExceeded => "virtual-memory-budget",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::Privilege(status)
            | Self::PrivilegeRestore(status)
            | Self::RangeProbe(status)
            | Self::RangeQuery(status)
            | Self::PrivateSourceProbe(status)
            | Self::PrivateSourceQuery(status)
            | Self::PfnQuery(status) => status as u32,
            Self::Physical(error) => error.code(),
            Self::InvalidProcess | Self::InvalidVirtualAddress => 487,
            Self::InvalidLength => 87,
            Self::Allocation => 8,
            Self::ProcessNotFound | Self::NotPresent => 1168,
            Self::AddressOverflow => 534,
            Self::InvalidResponse => 13,
            Self::BudgetExceeded => 1816,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SuperfetchInformation {
    version: u32,
    magic: u32,
    information_class: u32,
    reserved: u32,
    data: *mut c_void,
    length: u32,
    reserved2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PhysicalMemoryRange {
    base_pfn: usize,
    page_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MemoryRangeQuery {
    version: u32,
    flags: u32,
    range_count: u32,
    reserved: u32,
    first_range: PhysicalMemoryRange,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivatePageSource {
    source_type: u32,
    process_id: u32,
    image_path_hash: u32,
    reserved: u32,
    unique_process_hash: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivateSourceInformation {
    database: PrivatePageSource,
    process: usize,
    working_set_private_size: usize,
    private_pages: usize,
    session_id: u32,
    image_name: [u8; 16],
    reserved_alignment: u32,
    working_set_swap_pages: usize,
    working_set_total_pages: usize,
    deep_freeze_time_ms: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivateSourceQuery {
    version: u32,
    flags: u32,
    information_count: u32,
    reserved: u32,
    first_information: PrivateSourceInformation,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SystemMemoryListInformation {
    zero_page_count: usize,
    free_page_count: usize,
    modified_page_count: usize,
    modified_no_write_page_count: usize,
    bad_page_count: usize,
    page_count_by_priority: [usize; 8],
    repurposed_pages_by_priority: [usize; 8],
    modified_page_count_page_file: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfnQueryHeader {
    version: u32,
    request_flags: u32,
    pfn_count: usize,
    memory_information: SystemMemoryListInformation,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfnIdentity {
    information: u64,
    page_frame_index: usize,
    virtual_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PageMapEntry {
    virtual_page: u64,
    physical_page: u64,
}

struct PageMap {
    entries: HeapBuffer,
    count: usize,
    snapshot_pages: usize,
}

impl PageMap {
    fn entries(&self) -> &[PageMapEntry] {
        // SAFETY: VirtualAlloc supplies alignment suitable for PageMapEntry,
        // and construction reserves at least count complete entries.
        unsafe {
            slice::from_raw_parts(
                self.entries.as_slice().as_ptr().cast::<PageMapEntry>(),
                self.count,
            )
        }
    }

    fn entries_mut(&mut self) -> &mut [PageMapEntry] {
        // SAFETY: This is the only mutable view of the owned allocation, and
        // construction reserves MAX_TARGET_PAGES complete entries.
        unsafe {
            slice::from_raw_parts_mut(
                self.entries
                    .as_mut_slice()
                    .as_mut_ptr()
                    .cast::<PageMapEntry>(),
                MAX_TARGET_PAGES,
            )
        }
    }

    fn translate(&self, virtual_address: u64) -> Option<u64> {
        let page = virtual_address >> 12;
        let entry = lookup_entry(self.entries(), page)?;

        entry
            .physical_page
            .checked_shl(12)
            .and_then(|base| base.checked_add(virtual_address & 0xfff))
    }
}

pub struct ProcessMemory<'a, A: KernelAdapter> {
    adapter: &'a mut A,
    map: PageMap,
    reads: usize,
    writes: usize,
    translations: usize,
    misses: usize,
}

impl<'a, A: KernelAdapter> ProcessMemory<'a, A> {
    pub fn new(adapter: &'a mut A, process_id: u32) -> Result<Self, VirtualMemoryError> {
        if process_id <= 4 {
            return Err(VirtualMemoryError::InvalidProcess);
        }

        let mut privilege = ProfilePrivilege::enable()?;
        let ranges = query_ranges()?;
        let process_key = query_process_key(process_id)?;
        let map = build_page_map(&ranges, process_key)?;
        privilege.restore()?;

        Ok(Self {
            adapter,
            map,
            reads: 0,
            writes: 0,
            translations: 0,
            misses: 0,
        })
    }

    pub fn translate(&mut self, virtual_address: u64) -> Result<u64, VirtualMemoryError> {
        if !valid_virtual_address(virtual_address) {
            return Err(VirtualMemoryError::InvalidVirtualAddress);
        }

        let Some(physical) = self.map.translate(virtual_address) else {
            self.misses += 1;
            return Err(VirtualMemoryError::NotPresent);
        };

        self.translations += 1;

        Ok(physical)
    }

    pub fn read(&mut self, mut address: u64, output: &mut [u8]) -> Result<(), VirtualMemoryError> {
        validate_transfer(address, output.len())?;
        let mut offset = 0;

        while offset < output.len() {
            if self.reads >= MAX_PHYSICAL_READS {
                return Err(VirtualMemoryError::BudgetExceeded);
            }

            let page_offset = address as usize & (PAGE_BYTES - 1);
            let chunk = core::cmp::min(PAGE_BYTES - page_offset, output.len() - offset);
            match self.translate(address) {
                Ok(physical) => {
                    self.adapter
                        .read_physical(physical, &mut output[offset..offset + chunk])
                        .map_err(VirtualMemoryError::Physical)?;
                    self.reads += 1;
                }
                Err(VirtualMemoryError::NotPresent) => {
                    zero(&mut output[offset..offset + chunk]);
                }
                Err(error) => return Err(error),
            }
            address = address
                .checked_add(chunk as u64)
                .ok_or(VirtualMemoryError::AddressOverflow)?;
            offset += chunk;
        }

        Ok(())
    }

    pub fn write(&mut self, mut address: u64, input: &[u8]) -> Result<(), VirtualMemoryError> {
        validate_transfer(address, input.len())?;
        let mut offset = 0;

        while offset < input.len() {
            if self.writes >= MAX_PHYSICAL_WRITES {
                return Err(VirtualMemoryError::BudgetExceeded);
            }

            let page_offset = address as usize & (PAGE_BYTES - 1);
            let chunk = core::cmp::min(PAGE_BYTES - page_offset, input.len() - offset);
            let physical = self.translate(address)?;
            self.adapter
                .write_physical(physical, &input[offset..offset + chunk])
                .map_err(VirtualMemoryError::Physical)?;
            self.writes += 1;
            address = address
                .checked_add(chunk as u64)
                .ok_or(VirtualMemoryError::AddressOverflow)?;
            offset += chunk;
        }

        Ok(())
    }

    pub fn read_u32(&mut self, address: u64) -> Result<u32, VirtualMemoryError> {
        let mut bytes = [0_u8; 4];
        self.read(address, &mut bytes)?;
        let value = u32::from_le_bytes(bytes);
        zero(&mut bytes);

        Ok(value)
    }

    pub fn read_u64(&mut self, address: u64) -> Result<u64, VirtualMemoryError> {
        let mut bytes = [0_u8; 8];
        self.read(address, &mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        zero(&mut bytes);

        Ok(value)
    }

    pub const fn reads(&self) -> usize {
        self.reads
    }

    pub const fn writes(&self) -> usize {
        self.writes
    }

    pub const fn translations(&self) -> usize {
        self.translations
    }

    pub const fn misses(&self) -> usize {
        self.misses
    }

    pub const fn mapped_pages(&self) -> usize {
        self.map.count
    }

    pub const fn snapshot_pages(&self) -> usize {
        self.map.snapshot_pages
    }
}

struct QueryBuffer {
    buffer: HeapBuffer,
    length: usize,
}

fn query_ranges() -> Result<QueryBuffer, VirtualMemoryError> {
    let mut initial = MemoryRangeQuery {
        version: 2,
        ..MemoryRangeQuery::default()
    };
    let mut required = 0_u32;
    let status = query_superfetch(
        SUPERFETCH_MEMORY_RANGES_QUERY,
        (&mut initial as *mut MemoryRangeQuery).cast(),
        size_of::<MemoryRangeQuery>(),
        &mut required,
    );

    if !buffer_probe_status(status) {
        return Err(VirtualMemoryError::RangeProbe(status));
    }

    let length = required as usize;

    if !(16..=MAX_RANGE_BYTES).contains(&length) {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    let mut buffer = HeapBuffer::new(length).ok_or(VirtualMemoryError::Allocation)?;
    buffer.as_mut_slice()[..4].copy_from_slice(&2_u32.to_le_bytes());
    required = 0;
    let status = query_superfetch(
        SUPERFETCH_MEMORY_RANGES_QUERY,
        buffer.as_mut_slice().as_mut_ptr().cast(),
        length,
        &mut required,
    );

    if !nt_success(status) {
        return Err(VirtualMemoryError::RangeQuery(status));
    }

    let returned = if required == 0 {
        length
    } else {
        required as usize
    };

    if returned < 16 || returned > length {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    Ok(QueryBuffer {
        buffer,
        length: returned,
    })
}

fn query_process_key(process_id: u32) -> Result<u64, VirtualMemoryError> {
    let mut initial = PrivateSourceQuery {
        version: 8,
        ..PrivateSourceQuery::default()
    };
    let mut required = 0_u32;
    let status = query_superfetch(
        SUPERFETCH_PRIVATE_SOURCE_QUERY,
        (&mut initial as *mut PrivateSourceQuery).cast(),
        size_of::<PrivateSourceQuery>(),
        &mut required,
    );

    if !buffer_probe_status(status) {
        return Err(VirtualMemoryError::PrivateSourceProbe(status));
    }

    let length = required as usize;

    if !(16..=MAX_PRIVATE_SOURCE_BYTES).contains(&length) {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    let mut buffer = HeapBuffer::new(length).ok_or(VirtualMemoryError::Allocation)?;
    buffer.as_mut_slice()[..4].copy_from_slice(&8_u32.to_le_bytes());
    required = 0;
    let status = query_superfetch(
        SUPERFETCH_PRIVATE_SOURCE_QUERY,
        buffer.as_mut_slice().as_mut_ptr().cast(),
        length,
        &mut required,
    );

    if !nt_success(status) {
        return Err(VirtualMemoryError::PrivateSourceQuery(status));
    }

    let returned = if required == 0 {
        length
    } else {
        required as usize
    };
    let information_count =
        read_u32(buffer.as_slice(), 8).ok_or(VirtualMemoryError::InvalidResponse)? as usize;
    let information_bytes = information_count
        .checked_mul(size_of::<PrivateSourceInformation>())
        .and_then(|value| value.checked_add(16))
        .ok_or(VirtualMemoryError::AddressOverflow)?;

    if returned < 16 || returned > length || information_bytes > returned {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    for index in 0..information_count {
        let offset = 16 + index * size_of::<PrivateSourceInformation>();
        // SAFETY: The complete fixed-size item was bounded against the returned
        // response above. read_unaligned avoids layout assumptions on the byte buffer.
        let information = unsafe {
            ptr::read_unaligned(
                buffer
                    .as_slice()
                    .as_ptr()
                    .add(offset)
                    .cast::<PrivateSourceInformation>(),
            )
        };

        if information.database.source_type == 2 && information.database.process_id == process_id {
            let key = information.process as u64 & PROCESS_KEY_MASK;

            return if key == 0 {
                Err(VirtualMemoryError::InvalidResponse)
            } else {
                Ok(key)
            };
        }
    }

    Err(VirtualMemoryError::ProcessNotFound)
}

fn build_page_map(ranges: &QueryBuffer, process_key: u64) -> Result<PageMap, VirtualMemoryError> {
    let range_count =
        read_u32(ranges.buffer.as_slice(), 8).ok_or(VirtualMemoryError::InvalidResponse)? as usize;
    let range_bytes = range_count
        .checked_mul(size_of::<PhysicalMemoryRange>())
        .and_then(|value| value.checked_add(16))
        .ok_or(VirtualMemoryError::AddressOverflow)?;

    if range_count == 0 || range_count > MAX_RANGES || range_bytes > ranges.length {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    let mut total_pages = 0_usize;

    for index in 0..range_count {
        let range = read_range(ranges.buffer.as_slice(), index)?;
        total_pages = total_pages
            .checked_add(range.page_count)
            .filter(|total| *total <= MAX_PHYSICAL_PAGES)
            .ok_or(VirtualMemoryError::InvalidResponse)?;
    }

    if total_pages == 0 {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    let query_bytes = total_pages
        .checked_mul(size_of::<PfnIdentity>())
        .and_then(|value| value.checked_add(size_of::<PfnQueryHeader>()))
        .filter(|length| *length <= MAX_QUERY_BYTES)
        .ok_or(VirtualMemoryError::AddressOverflow)?;
    let mut query = HeapBuffer::new_large(query_bytes).ok_or(VirtualMemoryError::Allocation)?;
    let header = PfnQueryHeader {
        version: 1,
        request_flags: 1,
        pfn_count: total_pages,
        memory_information: SystemMemoryListInformation::default(),
    };

    // SAFETY: The allocation is aligned and at least the exact header size.
    unsafe {
        query
            .as_mut_slice()
            .as_mut_ptr()
            .cast::<PfnQueryHeader>()
            .write(header);
    }

    let mut output_index = 0_usize;

    for index in 0..range_count {
        let range = read_range(ranges.buffer.as_slice(), index)?;

        for page in 0..range.page_count {
            let page_frame_index = range
                .base_pfn
                .checked_add(page)
                .ok_or(VirtualMemoryError::AddressOverflow)?;
            let identity = PfnIdentity {
                page_frame_index,
                ..PfnIdentity::default()
            };
            let offset = size_of::<PfnQueryHeader>() + output_index * size_of::<PfnIdentity>();

            // SAFETY: query_bytes was computed for total_pages entries and
            // output_index never exceeds that exact count.
            unsafe {
                query
                    .as_mut_slice()
                    .as_mut_ptr()
                    .add(offset)
                    .cast::<PfnIdentity>()
                    .write_unaligned(identity);
            }

            output_index += 1;
        }
    }

    let mut returned = 0_u32;
    let status = query_superfetch(
        SUPERFETCH_PFN_QUERY,
        query.as_mut_slice().as_mut_ptr().cast(),
        query_bytes,
        &mut returned,
    );

    if !nt_success(status) {
        return Err(VirtualMemoryError::PfnQuery(status));
    }

    let entry_bytes = MAX_TARGET_PAGES
        .checked_mul(size_of::<PageMapEntry>())
        .ok_or(VirtualMemoryError::AddressOverflow)?;
    let entries = HeapBuffer::new(entry_bytes).ok_or(VirtualMemoryError::Allocation)?;
    let mut map = PageMap {
        entries,
        count: 0,
        snapshot_pages: total_pages,
    };

    for index in 0..total_pages {
        let offset = size_of::<PfnQueryHeader>() + index * size_of::<PfnIdentity>();
        // SAFETY: The PFN query buffer contains exactly total_pages fixed-size
        // identities after the bounded header.
        let identity = unsafe {
            ptr::read_unaligned(query.as_slice().as_ptr().add(offset).cast::<PfnIdentity>())
        };
        let use_description = identity.information & 0xf;
        let list_description = (identity.information >> 4) & 0x7;
        let identity_key = (identity.information >> 9) & PROCESS_KEY_MASK;

        if use_description != PROCESS_PRIVATE
            || list_description != ACTIVE_AND_VALID
            || identity_key != process_key
            || !valid_user_address(identity.virtual_address)
            || identity.virtual_address & 0xfff != 0
        {
            continue;
        }

        if map.count == MAX_TARGET_PAGES {
            return Err(VirtualMemoryError::InvalidResponse);
        }

        let count = map.count;
        map.entries_mut()[count] = PageMapEntry {
            virtual_page: identity.virtual_address >> 12,
            physical_page: identity.page_frame_index as u64,
        };
        map.count += 1;
    }

    if map.count == 0 {
        return Err(VirtualMemoryError::NotPresent);
    }

    let count = map.count;
    shell_sort_entries(&mut map.entries_mut()[..count]);

    Ok(map)
}

fn read_range(input: &[u8], index: usize) -> Result<PhysicalMemoryRange, VirtualMemoryError> {
    let offset = 16_usize
        .checked_add(
            index
                .checked_mul(size_of::<PhysicalMemoryRange>())
                .ok_or(VirtualMemoryError::AddressOverflow)?,
        )
        .ok_or(VirtualMemoryError::AddressOverflow)?;

    if offset + size_of::<PhysicalMemoryRange>() > input.len() {
        return Err(VirtualMemoryError::InvalidResponse);
    }

    // SAFETY: The complete fixed-size range was bounded above.
    Ok(unsafe { ptr::read_unaligned(input.as_ptr().add(offset).cast::<PhysicalMemoryRange>()) })
}

fn lookup_entry(entries: &[PageMapEntry], page: u64) -> Option<PageMapEntry> {
    let mut low = 0;
    let mut high = entries.len();

    while low < high {
        let middle = low + (high - low) / 2;

        if entries[middle].virtual_page < page {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    entries
        .get(low)
        .copied()
        .filter(|entry| entry.virtual_page == page)
}

fn shell_sort_entries(entries: &mut [PageMapEntry]) {
    let mut gap = entries.len() / 2;

    while gap != 0 {
        let mut index = gap;

        while index < entries.len() {
            let temporary = entries[index];
            let mut scan = index;

            while scan >= gap && entries[scan - gap].virtual_page > temporary.virtual_page {
                entries[scan] = entries[scan - gap];
                scan -= gap;
            }

            entries[scan] = temporary;
            index += 1;
        }

        gap /= 2;
    }
}

fn validate_transfer(address: u64, length: usize) -> Result<(), VirtualMemoryError> {
    if length == 0 || length > MAX_TRANSFER_BYTES {
        return Err(VirtualMemoryError::InvalidLength);
    }

    if !valid_virtual_address(address)
        || address
            .checked_add(length as u64 - 1)
            .is_none_or(|end| !valid_virtual_address(end))
    {
        return Err(VirtualMemoryError::InvalidVirtualAddress);
    }

    Ok(())
}

pub const fn valid_user_address(address: u64) -> bool {
    address >= 0x1_0000 && address < 0x0000_8000_0000_0000
}

const fn valid_virtual_address(address: u64) -> bool {
    valid_user_address(address) || address >= 0xffff_8000_0000_0000
}

const fn nt_success(status: i32) -> bool {
    status >= 0
}

const fn buffer_probe_status(status: i32) -> bool {
    status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH
}

#[cfg(not(test))]
fn query_superfetch(
    information_class: u32,
    data: *mut c_void,
    length: usize,
    returned: &mut u32,
) -> i32 {
    if length > u32::MAX as usize {
        return 0xc000_000d_u32 as i32;
    }

    let mut information = SuperfetchInformation {
        version: SUPERFETCH_VERSION,
        magic: SUPERFETCH_MAGIC,
        information_class,
        reserved: 0,
        data,
        length: length as u32,
        reserved2: 0,
    };

    // SAFETY: information and its bounded data buffer remain live and writable
    // for the complete native query.
    unsafe {
        nt_query_system_information(
            SYSTEM_SUPERFETCH_INFORMATION,
            (&mut information as *mut SuperfetchInformation).cast(),
            size_of::<SuperfetchInformation>() as u32,
            returned,
        )
    }
}

#[cfg(test)]
fn query_superfetch(
    _information_class: u32,
    _data: *mut c_void,
    _length: usize,
    _returned: &mut u32,
) -> i32 {
    0xc000_00bb_u32 as i32
}

struct ProfilePrivilege {
    previous: u8,
    active: bool,
}

impl ProfilePrivilege {
    #[cfg(not(test))]
    fn enable() -> Result<Self, VirtualMemoryError> {
        let mut previous = 0_u8;

        // SAFETY: previous points to one writable BOOLEAN and the privilege is
        // adjusted only for the current process.
        let status = unsafe {
            rtl_adjust_privilege(SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, 1, 0, &mut previous)
        };

        if !nt_success(status) {
            return Err(VirtualMemoryError::Privilege(status));
        }

        Ok(Self {
            previous,
            active: true,
        })
    }

    #[cfg(test)]
    fn enable() -> Result<Self, VirtualMemoryError> {
        Err(VirtualMemoryError::Privilege(0xc000_00bb_u32 as i32))
    }

    #[cfg(not(test))]
    fn restore(&mut self) -> Result<(), VirtualMemoryError> {
        if !self.active {
            return Ok(());
        }

        let mut ignored = 0_u8;

        // SAFETY: ignored points to one writable BOOLEAN and previous contains
        // the state returned by the matching process-wide enable call.
        let status = unsafe {
            rtl_adjust_privilege(
                SE_PROFILE_SINGLE_PROCESS_PRIVILEGE,
                self.previous,
                0,
                &mut ignored,
            )
        };

        if !nt_success(status) {
            return Err(VirtualMemoryError::PrivilegeRestore(status));
        }

        self.active = false;

        Ok(())
    }

    #[cfg(test)]
    fn restore(&mut self) -> Result<(), VirtualMemoryError> {
        self.active = false;

        Ok(())
    }
}

impl Drop for ProfilePrivilege {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        #[cfg(not(test))]
        {
            let mut ignored = 0_u8;

            // SAFETY: This is a best-effort restoration of the privilege state
            // captured by the matching enable call.
            let status = unsafe {
                rtl_adjust_privilege(
                    SE_PROFILE_SINGLE_PROCESS_PRIVILEGE,
                    self.previous,
                    0,
                    &mut ignored,
                )
            };

            self.active = !nt_success(status);
        }

        #[cfg(test)]
        {
            self.active = false;
        }
    }
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "NtQuerySystemInformation"]
    fn nt_query_system_information(
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    #[link_name = "RtlAdjustPrivilege"]
    fn rtl_adjust_privilege(
        privilege: u32,
        enable: u8,
        current_thread: u8,
        previous: *mut u8,
    ) -> i32;
}

fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = input.get(offset..offset + 4)?.try_into().ok()?;

    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_layouts_match_the_x64_superfetch_contract() {
        assert_eq!(size_of::<SuperfetchInformation>(), 32);
        assert_eq!(size_of::<PhysicalMemoryRange>(), 16);
        assert_eq!(size_of::<PrivateSourceInformation>(), 96);
        assert_eq!(size_of::<PfnQueryHeader>(), 192);
        assert_eq!(size_of::<PfnIdentity>(), 24);
    }

    #[test]
    fn sorts_and_finds_exact_virtual_pages() {
        let mut entries = [
            PageMapEntry {
                virtual_page: 9,
                physical_page: 90,
            },
            PageMapEntry {
                virtual_page: 1,
                physical_page: 10,
            },
            PageMapEntry {
                virtual_page: 5,
                physical_page: 50,
            },
        ];

        shell_sort_entries(&mut entries);

        assert_eq!(entries[0].virtual_page, 1);
        assert_eq!(entries[2].virtual_page, 9);
        assert_eq!(lookup_entry(&entries, 5).unwrap().physical_page, 50);
        assert!(lookup_entry(&entries, 6).is_none());
    }

    #[test]
    fn extracts_frame_state_and_process_key_from_one_identity_word() {
        let process_key = 0x1234_5678_9abc;
        let information = PROCESS_PRIVATE | (ACTIVE_AND_VALID << 4) | (process_key << 9);

        assert_eq!(information & 0xf, PROCESS_PRIVATE);
        assert_eq!((information >> 4) & 0x7, ACTIVE_AND_VALID);
        assert_eq!((information >> 9) & PROCESS_KEY_MASK, process_key);
    }

    #[test]
    fn rejects_invalid_transfer_boundaries() {
        assert_eq!(
            validate_transfer(0x1_0000, 0),
            Err(VirtualMemoryError::InvalidLength)
        );
        assert_eq!(
            validate_transfer(0x1000, 8),
            Err(VirtualMemoryError::InvalidVirtualAddress)
        );
    }
}
