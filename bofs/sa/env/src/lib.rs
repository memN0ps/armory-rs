#![no_std]

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Environment::{
    FreeEnvironmentStringsA, GetEnvironmentStrings
};

#[rustbof::main]
fn main() {
    let env = unsafe { GetEnvironmentStrings() };
    if env.is_null() {
        eprintln!("Failed to retrieve environment variables");
        return;
    }

    println!("All environment variables:");
    for s in Env::from_ptr(env as *const u8) {
        let str_val = unsafe { core::str::from_utf8_unchecked(s) };
        println!("{str_val}");
    }

    unsafe { FreeEnvironmentStringsA(env) };
}

pub struct Env {
    ptr: *const u8,
}

impl Env {
    pub fn from_ptr(ptr: *const u8) -> Self {
        Self { ptr }
    }
}

impl Iterator for Env {
    type Item = &'static [u8];

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.ptr.is_null() {
                return None;
            }

            if *self.ptr == 0 && *self.ptr.add(1) == 0 {
                return None;
            }

            let mut len = 0;
            while *self.ptr.add(len) != 0 {
                len += 1;
            }

            if len == 0 {
                return None;
            }

            let slice = core::slice::from_raw_parts(self.ptr, len);
            self.ptr = self.ptr.add(len + 1);
            Some(slice)
        }
    }
}
