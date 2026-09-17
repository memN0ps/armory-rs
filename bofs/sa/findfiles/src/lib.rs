//! # Bounded File Search BOF
//!
//! Searches a directory tree for a case-insensitive wildcard pattern. The
//! maximum depth and result count are mandatory bounds, and reparse points are
//! never traversed.
//!
//! ## MITRE ATT&CK
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! - `str`: Root directory.
//! - `str`: File-name pattern using `*` and `?`.
//! - `int`: Maximum directory depth, from 0 through 32.
//! - `int`: Maximum results, from 1 through 1000.

#![no_std]

use alloc::{format, string::String, vec::Vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FindClose, FindFirstFileW,
    FindNextFileW, WIN32_FIND_DATAW,
};

struct WorkItem {
    path: String,
    depth: u32,
}

struct PackedArgs<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> PackedArgs<'a> {
    fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < 4 {
            return None;
        }

        let declared = u32::from_le_bytes(buffer[..4].try_into().ok()?) as usize;
        if declared != buffer.len() - 4 {
            return None;
        }

        Some(Self { buffer, offset: 4 })
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.offset.checked_add(4)?;
        let value = u32::from_le_bytes(self.buffer.get(self.offset..end)?.try_into().ok()?);
        self.offset = end;
        Some(value)
    }

    fn read_i32(&mut self) -> Option<i32> {
        self.read_u32().map(|value| value as i32)
    }

    fn read_string(&mut self) -> Option<&'a str> {
        let length = self.read_u32()? as usize;
        if length == 0 {
            return None;
        }

        let end = self.offset.checked_add(length)?;
        let bytes = self.buffer.get(self.offset..end)?;
        self.offset = end;
        if bytes.last().copied() != Some(0) || bytes[..length - 1].contains(&0) {
            return None;
        }

        core::str::from_utf8(&bytes[..length - 1]).ok()
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

const MAX_DIRECTORIES: u32 = 4096;
const MAX_PATH_UNITS: usize = 32760;

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_to_string(buffer: &[u16]) -> String {
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();
    let mut p = 0usize;
    let mut c = 0usize;
    let mut star = None;
    let mut retry = 0usize;

    while c < candidate.len() {
        if p < pattern.len()
            && (pattern[p] == b'?' || pattern[p].eq_ignore_ascii_case(&candidate[c]))
        {
            p += 1;
            c += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = c;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            c = retry;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn search(root: &str, pattern: &str, max_depth: u32, max_results: u32) {
    let mut pending = Vec::new();
    pending.push(WorkItem {
        path: root.trim_end_matches(['\\', '/']).into(),
        depth: 0,
    });

    let mut matches = 0u32;
    let mut directories = 0u32;
    let mut errors = 0u32;
    let mut tree_limited = false;

    while let Some(item) = pending.pop() {
        if matches >= max_results || directories >= MAX_DIRECTORIES {
            tree_limited = directories >= MAX_DIRECTORIES;
            break;
        }

        let query = wide_null(&format!("{}\\*", item.path));
        unsafe {
            let mut data: WIN32_FIND_DATAW = core::mem::zeroed();
            let handle = FindFirstFileW(query.as_ptr(), &mut data);
            if handle == INVALID_HANDLE_VALUE {
                errors += 1;
                continue;
            }
            directories += 1;

            loop {
                let name = wide_to_string(&data.cFileName);
                if name != "." && name != ".." {
                    let full_path = format!("{}\\{}", item.path, name);
                    let is_directory = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
                    let is_reparse = data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;

                    if is_directory {
                        if !is_reparse && item.depth < max_depth {
                            if full_path.encode_utf16().count() < MAX_PATH_UNITS
                                && directories.saturating_add(pending.len() as u32)
                                    < MAX_DIRECTORIES
                            {
                                pending.push(WorkItem {
                                    path: full_path,
                                    depth: item.depth + 1,
                                });
                            } else {
                                tree_limited = true;
                            }
                        }
                    } else if wildcard_match(pattern, &name) {
                        println!("{}", full_path);
                        matches += 1;
                        if matches >= max_results {
                            break;
                        }
                    }
                }

                if FindNextFileW(handle, &mut data) == 0 {
                    if GetLastError() != ERROR_NO_MORE_FILES {
                        errors += 1;
                    }
                    break;
                }
            }

            FindClose(handle);
        }
    }

    println!(
        "\nMatches: {} | directories searched: {} | inaccessible/error: {}{}",
        matches,
        directories,
        errors,
        if matches >= max_results {
            " | result limit reached"
        } else if tree_limited {
            " | directory/path limit reached"
        } else {
            ""
        }
    );
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    if args.is_null() || len == 0 {
        eprintln!("Usage: findfiles <root> <pattern> <max_depth 0-32> <max_results 1-1000>");
    } else {
        // SAFETY: The BOF ABI supplies `args` as a readable buffer of exactly
        // `len` bytes for the duration of this call. Every field is bounded and
        // checked before a slice or string is constructed.
        let packed = unsafe { core::slice::from_raw_parts(args, len) };
        let parsed = PackedArgs::new(packed).and_then(|mut parser| {
            let root = parser.read_string()?;
            let pattern = parser.read_string()?;
            let max_depth = parser.read_i32()?;
            let max_results = parser.read_i32()?;
            parser
                .finished()
                .then_some((root, pattern, max_depth, max_results))
        });

        match parsed {
            Some((root, pattern, max_depth, max_results))
                if !root.is_empty()
                    && root.len() <= 1024
                    && !pattern.is_empty()
                    && pattern.len() <= 260
                    && (0..=32).contains(&max_depth)
                    && (1..=1000).contains(&max_results) =>
            {
                println!(
                    "Searching {} for {} (depth {}, limit {})\n",
                    root, pattern, max_depth, max_results
                );
                search(root, pattern, max_depth as u32, max_results as u32);
            }
            _ => {
                eprintln!(
                    "Usage: findfiles <root> <pattern> <max_depth 0-32> <max_results 1-1000>"
                );
            }
        }
    }
}
