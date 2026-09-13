//! Minimal compiler runtime symbols used by the final COFF object.

use core::ffi::{c_int, c_void};

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    let mut offset = 0;

    while offset < count {
        // SAFETY: The compiler supplies readable ranges of at least `count`
        // bytes. Volatile reads prevent this compatibility symbol from being
        // optimized into a recursive call to itself.
        let left_byte = unsafe { left.add(offset).read_volatile() };
        let right_byte = unsafe { right.add(offset).read_volatile() };

        if left_byte != right_byte {
            return left_byte as c_int - right_byte as c_int;
        }

        offset += 1;
    }

    0
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    let mut offset = 0;

    while offset < count {
        // SAFETY: The compiler supplies non-overlapping readable and writable
        // ranges of at least `count` bytes for `memcpy`.
        let value = unsafe { source_bytes.add(offset).read_volatile() };
        unsafe { destination_bytes.add(offset).write_volatile(value) };
        offset += 1;
    }

    destination
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memset(
    destination: *mut c_void,
    value: c_int,
    count: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    let mut offset = 0;

    while offset < count {
        // SAFETY: The compiler supplies a writable range of at least `count`
        // bytes. Volatile writes avoid recursive lowering into `memset`.
        unsafe { destination_bytes.add(offset).write_volatile(value as u8) };
        offset += 1;
    }

    destination
}
