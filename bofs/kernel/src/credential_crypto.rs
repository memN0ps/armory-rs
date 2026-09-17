//! LSA secret decryption through direct CNG COFF imports.

use crate::{bytes::zero, heap::HeapBuffer};
use core::{ffi::c_void, ptr};

const MAX_SECRET_BYTES: usize = 0x1_0000;
const MAX_KEY_OBJECT_BYTES: usize = 0x4000;

const AES: &[u16] = &[b'A' as u16, b'E' as u16, b'S' as u16, 0];
const TRIPLE_DES: &[u16] = &[b'3' as u16, b'D' as u16, b'E' as u16, b'S' as u16, 0];
const CHAINING_MODE: &[u16] = &[
    b'C' as u16,
    b'h' as u16,
    b'a' as u16,
    b'i' as u16,
    b'n' as u16,
    b'i' as u16,
    b'n' as u16,
    b'g' as u16,
    b'M' as u16,
    b'o' as u16,
    b'd' as u16,
    b'e' as u16,
    0,
];
const CHAINING_CFB: &[u16] = &[
    b'C' as u16,
    b'h' as u16,
    b'a' as u16,
    b'i' as u16,
    b'n' as u16,
    b'i' as u16,
    b'n' as u16,
    b'g' as u16,
    b'M' as u16,
    b'o' as u16,
    b'd' as u16,
    b'e' as u16,
    b'C' as u16,
    b'F' as u16,
    b'B' as u16,
    0,
];
const CHAINING_CBC: &[u16] = &[
    b'C' as u16,
    b'h' as u16,
    b'a' as u16,
    b'i' as u16,
    b'n' as u16,
    b'i' as u16,
    b'n' as u16,
    b'g' as u16,
    b'M' as u16,
    b'o' as u16,
    b'd' as u16,
    b'e' as u16,
    b'C' as u16,
    b'B' as u16,
    b'C' as u16,
    0,
];
const MESSAGE_BLOCK_LENGTH: &[u16] = &[
    b'M' as u16,
    b'e' as u16,
    b's' as u16,
    b's' as u16,
    b'a' as u16,
    b'g' as u16,
    b'e' as u16,
    b'B' as u16,
    b'l' as u16,
    b'o' as u16,
    b'c' as u16,
    b'k' as u16,
    b'L' as u16,
    b'e' as u16,
    b'n' as u16,
    b'g' as u16,
    b't' as u16,
    b'h' as u16,
    0,
];
const OBJECT_LENGTH: &[u16] = &[
    b'O' as u16,
    b'b' as u16,
    b'j' as u16,
    b'e' as u16,
    b'c' as u16,
    b't' as u16,
    b'L' as u16,
    b'e' as u16,
    b'n' as u16,
    b'g' as u16,
    b't' as u16,
    b'h' as u16,
    0,
];

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidInput,
    Allocation,
    Open(i32),
    Property(i32),
    Key(i32),
    Decrypt(i32),
    InvalidOutput,
}

impl CryptoError {
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::InvalidInput => "credential-crypto-input",
            Self::Allocation => "credential-crypto-allocation",
            Self::Open(_) => "credential-crypto-provider",
            Self::Property(_) => "credential-crypto-property",
            Self::Key(_) => "credential-crypto-key",
            Self::Decrypt(_) => "credential-crypto-decrypt",
            Self::InvalidOutput => "credential-crypto-output",
        }
    }

    pub const fn code(&self) -> u32 {
        match self {
            Self::Open(status)
            | Self::Property(status)
            | Self::Key(status)
            | Self::Decrypt(status) => *status as u32,
            Self::Allocation => 8,
            Self::InvalidInput | Self::InvalidOutput => 13,
        }
    }
}

pub struct LsaKeys {
    pub iv: [u8; 16],
    pub aes: [u8; 32],
    pub des: [u8; 24],
    pub aes_length: usize,
    pub des_length: usize,
}

impl LsaKeys {
    pub const fn empty() -> Self {
        Self {
            iv: [0; 16],
            aes: [0; 32],
            des: [0; 24],
            aes_length: 0,
            des_length: 0,
        }
    }

    pub fn valid(&self) -> bool {
        self.iv.iter().any(|byte| *byte != 0)
            && self.aes_length >= 16
            && self.aes_length <= self.aes.len()
            && self.des_length == self.des.len()
    }
}

impl Drop for LsaKeys {
    fn drop(&mut self) {
        zero(&mut self.iv);
        zero(&mut self.aes);
        zero(&mut self.des);
        self.aes_length = 0;
        self.des_length = 0;
    }
}

pub struct SecretBuffer {
    bytes: HeapBuffer,
    length: usize,
}

impl SecretBuffer {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }
}

struct Algorithm(*mut c_void);

impl Drop for Algorithm {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle came from BCryptOpenAlgorithmProvider and is
            // closed exactly once here.
            unsafe {
                let _ = bcrypt_close_algorithm_provider(self.0, 0);
            }
        }
    }
}

struct Key(*mut c_void);

impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle came from BCryptGenerateSymmetricKey and is
            // destroyed exactly once here.
            unsafe {
                let _ = bcrypt_destroy_key(self.0);
            }
        }
    }
}

pub fn decrypt(input: &[u8], keys: &LsaKeys) -> Result<SecretBuffer, CryptoError> {
    if input.is_empty() || input.len() > MAX_SECRET_BYTES || !keys.valid() {
        return Err(CryptoError::InvalidInput);
    }

    let use_aes = input.len() % 8 != 0;
    let mut algorithm = ptr::null_mut();
    let provider = if use_aes { AES } else { TRIPLE_DES };
    let status = unsafe {
        bcrypt_open_algorithm_provider(&mut algorithm, provider.as_ptr(), ptr::null(), 0)
    };

    if status != 0 || algorithm.is_null() {
        return Err(CryptoError::Open(status));
    }

    let algorithm = Algorithm(algorithm);
    let chaining = if use_aes { CHAINING_CFB } else { CHAINING_CBC };
    let status = unsafe {
        bcrypt_set_property(
            algorithm.0,
            CHAINING_MODE.as_ptr(),
            chaining.as_ptr().cast_mut().cast(),
            (chaining.len() * 2) as u32,
            0,
        )
    };

    if status != 0 {
        return Err(CryptoError::Property(status));
    }

    if use_aes {
        let mut feedback = 16_u32;
        let status = unsafe {
            bcrypt_set_property(
                algorithm.0,
                MESSAGE_BLOCK_LENGTH.as_ptr(),
                (&mut feedback as *mut u32).cast(),
                size_of::<u32>() as u32,
                0,
            )
        };

        if status != 0 {
            return Err(CryptoError::Property(status));
        }
    }

    let mut object_length = 0_u32;
    let mut copied = 0_u32;
    let status = unsafe {
        bcrypt_get_property(
            algorithm.0,
            OBJECT_LENGTH.as_ptr(),
            (&mut object_length as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut copied,
            0,
        )
    };

    if status != 0 {
        return Err(CryptoError::Property(status));
    }

    if copied != size_of::<u32>() as u32
        || object_length == 0
        || object_length as usize > MAX_KEY_OBJECT_BYTES
    {
        return Err(CryptoError::InvalidOutput);
    }

    let mut key_object = HeapBuffer::new(object_length as usize).ok_or(CryptoError::Allocation)?;
    let mut key_handle = ptr::null_mut();
    let (key, key_length) = if use_aes {
        (&keys.aes[..16], 16_u32)
    } else {
        (&keys.des[..], keys.des.len() as u32)
    };
    let status = unsafe {
        bcrypt_generate_symmetric_key(
            algorithm.0,
            &mut key_handle,
            key_object.as_mut_slice().as_mut_ptr(),
            object_length,
            key.as_ptr().cast_mut(),
            key_length,
            0,
        )
    };

    if status != 0 || key_handle.is_null() {
        return Err(CryptoError::Key(status));
    }

    let key_handle = Key(key_handle);
    let mut encrypted = HeapBuffer::new(input.len()).ok_or(CryptoError::Allocation)?;
    encrypted.as_mut_slice().copy_from_slice(input);
    let mut output = HeapBuffer::new(input.len() + 16).ok_or(CryptoError::Allocation)?;
    let mut iv = keys.iv;
    let iv_length = if use_aes { 16 } else { 8 };
    let mut output_length = 0_u32;
    let status = unsafe {
        bcrypt_decrypt(
            key_handle.0,
            encrypted.as_mut_slice().as_mut_ptr(),
            input.len() as u32,
            ptr::null_mut(),
            iv.as_mut_ptr(),
            iv_length,
            output.as_mut_slice().as_mut_ptr(),
            input.len() as u32,
            &mut output_length,
            0,
        )
    };
    zero(&mut iv);

    if status != 0 {
        return Err(CryptoError::Decrypt(status));
    }

    if output_length == 0 || output_length as usize > input.len() {
        return Err(CryptoError::InvalidOutput);
    }

    Ok(SecretBuffer {
        bytes: output,
        length: output_length as usize,
    })
}

#[cfg(not(test))]
unsafe extern "system" {
    #[link_name = "BCryptOpenAlgorithmProvider"]
    fn bcrypt_open_algorithm_provider(
        algorithm: *mut *mut c_void,
        algorithm_id: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> i32;

    #[link_name = "BCryptSetProperty"]
    fn bcrypt_set_property(
        object: *mut c_void,
        property: *const u16,
        input: *mut u8,
        input_length: u32,
        flags: u32,
    ) -> i32;

    #[link_name = "BCryptGetProperty"]
    fn bcrypt_get_property(
        object: *mut c_void,
        property: *const u16,
        output: *mut u8,
        output_length: u32,
        result_length: *mut u32,
        flags: u32,
    ) -> i32;

    #[link_name = "BCryptGenerateSymmetricKey"]
    fn bcrypt_generate_symmetric_key(
        algorithm: *mut c_void,
        key: *mut *mut c_void,
        key_object: *mut u8,
        key_object_length: u32,
        secret: *mut u8,
        secret_length: u32,
        flags: u32,
    ) -> i32;

    #[link_name = "BCryptDecrypt"]
    fn bcrypt_decrypt(
        key: *mut c_void,
        input: *mut u8,
        input_length: u32,
        padding: *mut c_void,
        initialization_vector: *mut u8,
        initialization_vector_length: u32,
        output: *mut u8,
        output_length: u32,
        result_length: *mut u32,
        flags: u32,
    ) -> i32;

    #[link_name = "BCryptDestroyKey"]
    fn bcrypt_destroy_key(key: *mut c_void) -> i32;

    #[link_name = "BCryptCloseAlgorithmProvider"]
    fn bcrypt_close_algorithm_provider(algorithm: *mut c_void, flags: u32) -> i32;
}

#[cfg(test)]
unsafe fn bcrypt_open_algorithm_provider(
    _algorithm: *mut *mut c_void,
    _algorithm_id: *const u16,
    _implementation: *const u16,
    _flags: u32,
) -> i32 {
    -1
}

#[cfg(test)]
unsafe fn bcrypt_set_property(
    _object: *mut c_void,
    _property: *const u16,
    _input: *mut u8,
    _input_length: u32,
    _flags: u32,
) -> i32 {
    -1
}

#[cfg(test)]
unsafe fn bcrypt_get_property(
    _object: *mut c_void,
    _property: *const u16,
    _output: *mut u8,
    _output_length: u32,
    _result_length: *mut u32,
    _flags: u32,
) -> i32 {
    -1
}

#[cfg(test)]
unsafe fn bcrypt_generate_symmetric_key(
    _algorithm: *mut c_void,
    _key: *mut *mut c_void,
    _key_object: *mut u8,
    _key_object_length: u32,
    _secret: *mut u8,
    _secret_length: u32,
    _flags: u32,
) -> i32 {
    -1
}

#[cfg(test)]
unsafe fn bcrypt_decrypt(
    _key: *mut c_void,
    _input: *mut u8,
    _input_length: u32,
    _padding: *mut c_void,
    _initialization_vector: *mut u8,
    _initialization_vector_length: u32,
    _output: *mut u8,
    _output_length: u32,
    _result_length: *mut u32,
    _flags: u32,
) -> i32 {
    -1
}

#[cfg(test)]
unsafe fn bcrypt_destroy_key(_key: *mut c_void) -> i32 {
    0
}

#[cfg(test)]
unsafe fn bcrypt_close_algorithm_provider(_algorithm: *mut c_void, _flags: u32) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_require_exact_minimum_lengths() {
        let mut keys = LsaKeys::empty();
        assert!(!keys.valid());
        keys.iv[0] = 1;
        keys.aes_length = 16;
        keys.des_length = 24;
        assert!(keys.valid());
    }

    #[test]
    fn rejects_empty_ciphertext_before_calling_cng() {
        let mut keys = LsaKeys::empty();
        keys.iv[0] = 1;
        keys.aes_length = 16;
        keys.des_length = 24;
        assert_eq!(decrypt(&[], &keys).err(), Some(CryptoError::InvalidInput));
    }
}
