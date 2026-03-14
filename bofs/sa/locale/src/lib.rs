#![no_std]

use alloc::vec;
use rustbof::str::from_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Globalization::{
    GetDateFormatEx, GetLocaleInfoEx, GetSystemDefaultLocaleName, LocaleNameToLCID,
    DATE_LONGDATE, LOCALE_SENGLANGUAGE, LOCALE_SLOCALIZEDCOUNTRYNAME,
};

const BUF: i32 = 85;

#[rustbof::main]
fn main() {
    unsafe {
        let mut name = vec![0u16; BUF as usize];
        if GetSystemDefaultLocaleName(name.as_mut_ptr(), BUF) == 0 {
            eprintln!("Error retrieving system locale");
            return;
        }

        let mut lang = vec![0u16; BUF as usize];
        if GetLocaleInfoEx(name.as_ptr(), LOCALE_SENGLANGUAGE, lang.as_mut_ptr(), BUF) == 0 {
            eprintln!("Error retrieving language");
            return;
        }

        let lcid = LocaleNameToLCID(name.as_ptr(), 0);

        let mut date = vec![0u16; BUF as usize];
        GetDateFormatEx(
            name.as_ptr(), DATE_LONGDATE, core::ptr::null(),
            core::ptr::null(), date.as_mut_ptr(), BUF, core::ptr::null(),
        );

        let mut country = vec![0u16; BUF as usize];
        GetLocaleInfoEx(name.as_ptr(), LOCALE_SLOCALIZEDCOUNTRYNAME, country.as_mut_ptr(), BUF);

        println!("Locale: {} ({})", from_wide(&lang), from_wide(&name));
        println!("LCID: {:x}", lcid);
        println!("Date: {}", from_wide(&date));
        println!("Country: {}", from_wide(&country));
    }
}
