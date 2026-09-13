//! Checked byte decoding and small comparison helpers.

pub fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;

    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;

    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

pub fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset.checked_add(8)?)?;

    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

pub fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(output) = bytes.get_mut(offset..offset.saturating_add(4)) else {
        return false;
    };

    output.copy_from_slice(&value.to_le_bytes());

    true
}

pub fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> bool {
    let Some(output) = bytes.get_mut(offset..offset.saturating_add(8)) else {
        return false;
    };

    output.copy_from_slice(&value.to_le_bytes());

    true
}

pub const fn is_kernel_pointer(value: u64) -> bool {
    value & 0xffff_0000_0000_0000 == 0xffff_0000_0000_0000
}

pub fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

pub fn zero(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a unique reference to one live byte in the slice.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_decoders_reject_short_input() {
        assert_eq!(read_u16(&[1], 0), None);
        assert_eq!(read_u32(&[1, 2, 3], 0), None);
        assert_eq!(read_u64(&[0; 7], 0), None);
    }

    #[test]
    fn checked_encoders_reject_short_output() {
        let mut bytes = [0_u8; 8];

        assert!(write_u32(&mut bytes, 0, 0x4433_2211));
        assert_eq!(read_u32(&bytes, 0), Some(0x4433_2211));
        assert!(!write_u64(&mut bytes, 1, 1));
    }

    #[test]
    fn compares_ascii_without_case() {
        assert!(ascii_eq_ignore_case(b"NTOSKRNL.EXE", b"ntoskrnl.exe"));
        assert!(!ascii_eq_ignore_case(b"ntkrnlmp.exe", b"ntoskrnl.exe"));
    }

    #[test]
    fn recognizes_canonical_kernel_addresses() {
        assert!(is_kernel_pointer(0xffff_f800_0000_0000));
        assert!(!is_kernel_pointer(0x0000_7fff_0000_0000));
    }
}
