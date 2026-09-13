#![no_std]

use core::panic::PanicInfo;

unsafe extern "C" {
    fn BeaconOutput(kind: i32, data: *const u8, length: i32);
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(export_name = "go")]
pub extern "C" fn entry(_buffer: *const u8, _length: i32) {
    const MESSAGE: &[u8] = b"benign Rust BOF fixture\n";

    // SAFETY: The byte string is immutable and valid for the complete call.
    unsafe { BeaconOutput(0x20, MESSAGE.as_ptr(), MESSAGE.len() as i32) };
}
