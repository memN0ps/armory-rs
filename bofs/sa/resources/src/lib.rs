#![no_std]

use rustbof::{eprintln, println};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExA;

const DIV: u64 = 1_048_576;

#[rustbof::main]
fn main() {
    unsafe {
        let mut statex: MEMORYSTATUSEX = core::mem::zeroed();
        statex.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut statex) == 0 {
            eprintln!("Error fetching memory");
            return;
        }
        let used = (statex.ullTotalPhys - statex.ullAvailPhys) / DIV;
        let total = statex.ullTotalPhys / DIV;
        println!("Memory Used:\t{}MB/{}MB", used, total);

        let mut total_bytes: u64 = 0;
        let mut free_bytes: u64 = 0;
        if GetDiskFreeSpaceExA(
            core::ptr::null(), core::ptr::null_mut(),
            &mut total_bytes, &mut free_bytes,
        ) == 0 {
            eprintln!("Error fetching disk space");
            return;
        }
        println!("Free Space:\t{} MB", free_bytes / DIV);
        println!("Total Space:\t{} MB", total_bytes / DIV);
    }
}
