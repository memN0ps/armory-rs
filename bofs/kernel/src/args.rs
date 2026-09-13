//! Checked parser for standard Beacon-packed arguments.

use core::{slice, str};

const OUTER_LENGTH_BYTES: usize = 4;
const ITEM_LENGTH_BYTES: usize = 4;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentError {
    InvalidBuffer,
    InvalidLength,
    ItemTooLarge,
    MissingTerminator,
    InvalidUtf8,
}

impl ArgumentError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidBuffer => "invalid Beacon argument buffer",
            Self::InvalidLength => "invalid Beacon argument length",
            Self::ItemTooLarge => "Beacon argument exceeds the size limit",
            Self::MissingTerminator => "string argument is not terminated",
            Self::InvalidUtf8 => "string argument is not valid UTF-8",
        }
    }
}

pub struct Arguments<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Arguments<'a> {
    pub fn new(buffer: *const u8, length: i32) -> Result<Self, ArgumentError> {
        if length == 0 {
            return Ok(Self {
                bytes: &[],
                offset: 0,
            });
        }

        if buffer.is_null() || length < OUTER_LENGTH_BYTES as i32 {
            return Err(ArgumentError::InvalidBuffer);
        }

        let length = usize::try_from(length).map_err(|_| ArgumentError::InvalidLength)?;

        if length > MAX_ARGUMENT_BYTES {
            return Err(ArgumentError::ItemTooLarge);
        }

        // SAFETY: The BOF loader owns `buffer` for the duration of `go` and
        // supplies `length` as the accessible buffer size. The null, sign, and
        // upper-bound checks above run before this slice is created.
        let packed = unsafe { slice::from_raw_parts(buffer, length) };
        let declared = read_u32(packed, 0)? as usize;

        if declared != length - OUTER_LENGTH_BYTES {
            return Err(ArgumentError::InvalidLength);
        }

        Ok(Self {
            bytes: &packed[OUTER_LENGTH_BYTES..],
            offset: 0,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub fn string(&mut self) -> Result<&'a str, ArgumentError> {
        let length = read_u32(self.bytes, self.offset)? as usize;
        self.offset = self
            .offset
            .checked_add(ITEM_LENGTH_BYTES)
            .ok_or(ArgumentError::InvalidLength)?;

        if length == 0 || length > MAX_ARGUMENT_BYTES {
            return Err(ArgumentError::InvalidLength);
        }

        let end = self
            .offset
            .checked_add(length)
            .ok_or(ArgumentError::InvalidLength)?;

        if end > self.bytes.len() {
            return Err(ArgumentError::InvalidLength);
        }

        let raw = &self.bytes[self.offset..end];
        self.offset = end;

        if raw.last() != Some(&0) {
            return Err(ArgumentError::MissingTerminator);
        }

        str::from_utf8(&raw[..raw.len() - 1]).map_err(|_| ArgumentError::InvalidUtf8)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ArgumentError> {
    let end = offset
        .checked_add(ITEM_LENGTH_BYTES)
        .ok_or(ArgumentError::InvalidLength)?;
    let raw = bytes.get(offset..end).ok_or(ArgumentError::InvalidLength)?;

    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_string() {
        let packed = [5_u8, 0, 0, 0, 1, 0, 0, 0, 0];
        let mut args = Arguments::new(packed.as_ptr(), packed.len() as i32).unwrap();

        assert_eq!(args.string(), Ok(""));
        assert!(args.is_empty());
    }

    #[test]
    fn rejects_mismatched_outer_length() {
        let packed = [4_u8, 0, 0, 0, 1, 0, 0, 0, 0];

        assert!(matches!(
            Arguments::new(packed.as_ptr(), packed.len() as i32),
            Err(ArgumentError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_unterminated_string() {
        let packed = [5_u8, 0, 0, 0, 1, 0, 0, 0, b'x'];
        let mut args = Arguments::new(packed.as_ptr(), packed.len() as i32).unwrap();

        assert_eq!(args.string(), Err(ArgumentError::MissingTerminator));
    }
}
