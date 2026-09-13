//! Zeroing virtual-memory buffers for bounded BOF working sets.

use crate::bytes::zero;
use core::{ptr::NonNull, slice};

#[cfg(not(test))]
use core::ffi::c_void;

#[cfg(not(test))]
const MEM_COMMIT: u32 = 0x1000;
#[cfg(not(test))]
const MEM_RESERVE: u32 = 0x2000;
#[cfg(not(test))]
const MEM_RELEASE: u32 = 0x8000;
#[cfg(not(test))]
const PAGE_READWRITE: u32 = 0x04;
const MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_LARGE_BUFFER_BYTES: usize = 128 * 1024 * 1024;

pub struct HeapBuffer {
    address: NonNull<u8>,
    length: usize,
}

impl HeapBuffer {
    pub fn new(length: usize) -> Option<Self> {
        Self::new_bounded(length, MAX_BUFFER_BYTES)
    }

    pub fn new_large(length: usize) -> Option<Self> {
        Self::new_bounded(length, MAX_LARGE_BUFFER_BYTES)
    }

    fn new_bounded(length: usize, maximum: usize) -> Option<Self> {
        if length == 0 || length > maximum {
            return None;
        }

        let address = NonNull::new(allocate(length))?;

        Some(Self { address, length })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `address` owns a readable allocation of exactly `length`
        // bytes until this value is dropped.
        unsafe { slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `address` owns a unique writable allocation of exactly
        // `length` bytes until this value is dropped.
        unsafe { slice::from_raw_parts_mut(self.address.as_ptr(), self.length) }
    }

    pub const fn len(&self) -> usize {
        self.length
    }
}

impl Drop for HeapBuffer {
    fn drop(&mut self) {
        zero(self.as_mut_slice());
        let _ = release(self.address.as_ptr());
    }
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
}

#[cfg(not(test))]
fn allocate(length: usize) -> *mut u8 {
    // SAFETY: The request is bounded and asks Windows for a fresh private
    // read/write allocation.
    unsafe {
        virtual_alloc(
            core::ptr::null_mut(),
            length,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .cast()
    }
}

#[cfg(test)]
fn allocate(_length: usize) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(test))]
fn release(address: *mut u8) -> bool {
    // SAFETY: `address` was returned by VirtualAlloc and has not been freed.
    unsafe { virtual_free(address.cast(), 0, MEM_RELEASE) != 0 }
}

#[cfg(test)]
fn release(_address: *mut u8) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_buffers() {
        assert!(HeapBuffer::new(0).is_none());
        assert!(HeapBuffer::new(MAX_BUFFER_BYTES + 1).is_none());
        assert!(HeapBuffer::new_large(MAX_LARGE_BUFFER_BYTES + 1).is_none());
    }
}
