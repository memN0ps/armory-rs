//! Exact on-disk system PE section validation and bounded pattern scanning.

use crate::{
    bytes::{read_u16, read_u32},
    heap::HeapBuffer,
    system_image::{SystemImage, SystemImageError},
    user_module::UserModule,
};

const SECTION_BYTES: usize = 40;
const MAX_SECTIONS: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageSection {
    pub rva: u32,
    pub size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageScanError {
    InvalidImage,
    SectionNotFound,
    Allocation,
    PatternNotFound,
    PatternNotUnique,
    AddressOverflow,
    SystemImage(SystemImageError),
}

impl ImageScanError {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::InvalidImage => "image-scan-pe",
            Self::SectionNotFound => "image-scan-section",
            Self::Allocation => "image-scan-allocation",
            Self::PatternNotFound => "image-scan-pattern-not-found",
            Self::PatternNotUnique => "image-scan-pattern-not-unique",
            Self::AddressOverflow => "image-scan-address",
            Self::SystemImage(error) => error.stage(),
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            Self::SystemImage(error) => error.code(),
            Self::Allocation => 8,
            Self::PatternNotFound | Self::SectionNotFound => 1168,
            Self::InvalidImage | Self::PatternNotUnique => 13,
            Self::AddressOverflow => 534,
        }
    }
}

pub struct SectionImage {
    section: ImageSection,
    bytes: HeapBuffer,
}

impl SectionImage {
    pub fn read(
        module: UserModule,
        image_name: &[u8],
        section_name: &[u8],
    ) -> Result<Self, ImageScanError> {
        let image = SystemImage::open(image_name).map_err(ImageScanError::SystemImage)?;

        if image.identity() != module.identity || image.identity().image_size != module.size {
            return Err(ImageScanError::InvalidImage);
        }

        let raw = parse_section(image.bytes(), module.size, section_name)?;
        let mut bytes = HeapBuffer::new(raw.raw_size).ok_or(ImageScanError::Allocation)?;
        bytes
            .as_mut_slice()
            .copy_from_slice(&image.bytes()[raw.raw_offset..raw.raw_offset + raw.raw_size]);

        Ok(Self {
            section: raw.section,
            bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn find_unique(&self, pattern: &[u8]) -> Result<u32, ImageScanError> {
        find_unique(self.bytes(), pattern, None).and_then(|offset| {
            self.section
                .rva
                .checked_add(offset as u32)
                .ok_or(ImageScanError::AddressOverflow)
        })
    }

    pub fn find_unique_masked(&self, pattern: &[u8], mask: &[u8]) -> Result<u32, ImageScanError> {
        find_unique(self.bytes(), pattern, Some(mask)).and_then(|offset| {
            self.section
                .rva
                .checked_add(offset as u32)
                .ok_or(ImageScanError::AddressOverflow)
        })
    }

    pub fn displacement_target(&self, displacement_rva: u32) -> Result<u32, ImageScanError> {
        let offset = self.offset(displacement_rva, 4)?;
        let bytes = self
            .bytes()
            .get(offset..offset + 4)
            .ok_or(ImageScanError::InvalidImage)?;
        let displacement_bytes: [u8; 4] =
            bytes.try_into().map_err(|_| ImageScanError::InvalidImage)?;
        let displacement = i32::from_le_bytes(displacement_bytes) as i64;
        let next = displacement_rva as i64 + 4;
        let target = next
            .checked_add(displacement)
            .filter(|value| *value >= 0 && *value <= u32::MAX as i64)
            .ok_or(ImageScanError::AddressOverflow)?;

        Ok(target as u32)
    }

    pub fn read_u32(&self, rva: u32) -> Result<u32, ImageScanError> {
        let offset = self.offset(rva, 4)?;

        crate::bytes::read_u32(self.bytes(), offset).ok_or(ImageScanError::InvalidImage)
    }

    fn offset(&self, rva: u32, length: usize) -> Result<usize, ImageScanError> {
        let offset = rva
            .checked_sub(self.section.rva)
            .ok_or(ImageScanError::InvalidImage)? as usize;

        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.bytes.len())
        {
            return Err(ImageScanError::InvalidImage);
        }

        Ok(offset)
    }
}

struct RawSection {
    section: ImageSection,
    raw_offset: usize,
    raw_size: usize,
}

fn parse_section(image: &[u8], image_size: u32, name: &[u8]) -> Result<RawSection, ImageScanError> {
    if name.is_empty() || name.len() > 8 || read_u16(image, 0) != Some(0x5a4d) {
        return Err(ImageScanError::InvalidImage);
    }

    let nt = read_u32(image, 0x3c).ok_or(ImageScanError::InvalidImage)? as usize;

    if read_u32(image, nt) != Some(0x0000_4550) {
        return Err(ImageScanError::InvalidImage);
    }

    let count = read_u16(image, nt + 6).ok_or(ImageScanError::InvalidImage)? as usize;
    let optional = read_u16(image, nt + 20).ok_or(ImageScanError::InvalidImage)? as usize;
    let mut offset = nt
        .checked_add(24)
        .and_then(|value| value.checked_add(optional))
        .ok_or(ImageScanError::InvalidImage)?;

    if count == 0 || count > MAX_SECTIONS {
        return Err(ImageScanError::InvalidImage);
    }

    for _ in 0..count {
        let section = image
            .get(offset..offset + SECTION_BYTES)
            .ok_or(ImageScanError::InvalidImage)?;
        let section_name = section[..8].split(|byte| *byte == 0).next().unwrap_or(&[]);

        if section_name == name {
            let virtual_size = read_u32(section, 8).ok_or(ImageScanError::InvalidImage)?;
            let rva = read_u32(section, 12).ok_or(ImageScanError::InvalidImage)?;
            let raw_size = read_u32(section, 16).ok_or(ImageScanError::InvalidImage)?;
            let raw_offset = read_u32(section, 20).ok_or(ImageScanError::InvalidImage)?;
            let virtual_span = core::cmp::max(virtual_size, raw_size);
            let characteristics = read_u32(section, 36).ok_or(ImageScanError::InvalidImage)?;

            if raw_size == 0
                || rva
                    .checked_add(virtual_span)
                    .is_none_or(|end| end > image_size)
                || (raw_offset as usize)
                    .checked_add(raw_size as usize)
                    .is_none_or(|end| end > image.len())
                || characteristics & 0x2000_0000 == 0
            {
                return Err(ImageScanError::InvalidImage);
            }

            return Ok(RawSection {
                section: ImageSection {
                    rva,
                    size: raw_size,
                    characteristics,
                },
                raw_offset: raw_offset as usize,
                raw_size: raw_size as usize,
            });
        }

        offset += SECTION_BYTES;
    }

    Err(ImageScanError::SectionNotFound)
}

fn find_unique(bytes: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> Result<usize, ImageScanError> {
    if pattern.is_empty()
        || pattern.len() > bytes.len()
        || mask.is_some_and(|value| value.len() != pattern.len())
    {
        return Err(ImageScanError::PatternNotFound);
    }

    let mut found = None;

    for offset in 0..=bytes.len() - pattern.len() {
        let matched = pattern.iter().enumerate().all(|(index, expected)| {
            mask.map_or(bytes[offset + index] == *expected, |value| {
                value[index] == 0 || bytes[offset + index] == *expected
            })
        });

        if matched {
            if found.is_some() {
                return Err(ImageScanError::PatternNotUnique);
            }

            found = Some(offset);
        }
    }

    found.ok_or(ImageScanError::PatternNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_pattern_requires_one_match() {
        assert_eq!(find_unique(b"abcd", b"bc", None), Ok(1));
        assert_eq!(
            find_unique(b"abab", b"ab", None),
            Err(ImageScanError::PatternNotUnique)
        );
    }

    #[test]
    fn masked_pattern_ignores_wildcards() {
        assert_eq!(find_unique(b"abcde", b"axc", Some(&[1, 0, 1])), Ok(0));
    }
}
