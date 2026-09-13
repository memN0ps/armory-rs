//! Capability boundary between fixed actions and a reviewed driver backend.

pub const CONTRACT_VERSION: u32 = 1;
pub const MAX_TRANSFER_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Capability {
    KernelRead = 1 << 0,
    KernelWrite = 1 << 1,
    PhysicalRead = 1 << 2,
    PhysicalWrite = 1 << 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u32);

impl Capabilities {
    #[cfg(any(not(feature = "external-adapter"), test))]
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability as u32 != 0
    }

    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteSemantics(u32);

impl WriteSemantics {
    #[cfg(any(not(feature = "external-adapter"), test))]
    pub const NONE: Self = Self(0);
    pub const SINGLE_REQUEST: Self = Self(1 << 0);
    pub const EXACT_LENGTH: Self = Self(1 << 1);
    pub const READBACK_REQUIRED: Self = Self(1 << 2);
    pub const REQUIRED: Self =
        Self(Self::SINGLE_REQUEST.0 | Self::EXACT_LENGTH.0 | Self::READBACK_REQUIRED.0);

    #[cfg(feature = "external-adapter")]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterInfo {
    pub name: &'static str,
    pub contract_version: u32,
    pub capabilities: Capabilities,
    pub max_transfer: usize,
    pub kernel_alignment: usize,
    pub physical_alignment: usize,
    pub max_single_write: usize,
    pub write_semantics: WriteSemantics,
}

impl AdapterInfo {
    #[cfg(any(not(feature = "external-adapter"), test))]
    pub const fn unavailable() -> Self {
        Self {
            name: "not configured",
            contract_version: 0,
            capabilities: Capabilities::NONE,
            max_transfer: 0,
            kernel_alignment: 0,
            physical_alignment: 0,
            max_single_write: 0,
            write_semantics: WriteSemantics::NONE,
        }
    }

    pub fn validate(
        &self,
        required: Capabilities,
        required_write_bytes: usize,
    ) -> Result<(), AdapterError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(AdapterError::ContractVersion);
        }

        if self.max_transfer == 0 || self.max_transfer > MAX_TRANSFER_LIMIT {
            return Err(AdapterError::TransferLimit);
        }

        if self.kernel_alignment == 0 || !self.kernel_alignment.is_power_of_two() {
            return Err(AdapterError::KernelAlignment);
        }

        if self.physical_alignment == 0 || !self.physical_alignment.is_power_of_two() {
            return Err(AdapterError::PhysicalAlignment);
        }

        if !self.capabilities.contains_all(required) {
            return Err(AdapterError::Capability);
        }

        if required_write_bytes != 0 {
            if self.max_single_write == 0 || required_write_bytes > self.max_single_write {
                return Err(AdapterError::WriteLimit);
            }

            if !self.write_semantics.contains_all(WriteSemantics::REQUIRED) {
                return Err(AdapterError::WriteSemantics);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    Unavailable,
    ContractVersion,
    Capability,
    TransferLimit,
    KernelAlignment,
    PhysicalAlignment,
    WriteLimit,
    WriteSemantics,
    #[cfg(feature = "external-adapter")]
    InvalidAddress,
    #[cfg(feature = "external-adapter")]
    InvalidBuffer,
    #[cfg(feature = "external-adapter")]
    Backend(u32),
}

impl AdapterError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "adapter is not configured",
            Self::ContractVersion => "adapter contract version is not supported",
            Self::Capability => "adapter does not expose the required capability",
            Self::TransferLimit => "adapter transfer limit is invalid",
            Self::KernelAlignment => "adapter kernel alignment is invalid",
            Self::PhysicalAlignment => "adapter physical alignment is invalid",
            Self::WriteLimit => "adapter write limit is too small",
            Self::WriteSemantics => "adapter write semantics are incomplete",
            #[cfg(feature = "external-adapter")]
            Self::InvalidAddress => "adapter rejected the address",
            #[cfg(feature = "external-adapter")]
            Self::InvalidBuffer => "adapter rejected the transfer buffer",
            #[cfg(feature = "external-adapter")]
            Self::Backend(_) => "adapter backend request failed",
        }
    }

    pub const fn code(self) -> u32 {
        match self {
            #[cfg(feature = "external-adapter")]
            Self::Backend(code) => code,
            _ => 0,
        }
    }
}

pub trait KernelAdapter {
    fn info(&self) -> AdapterInfo;
    fn open(&mut self, required: Capabilities) -> Result<(), AdapterError>;
    fn close(&mut self) -> Result<(), AdapterError>;
    fn read_kernel(&mut self, address: u64, output: &mut [u8]) -> Result<(), AdapterError>;
    fn write_kernel(&mut self, address: u64, input: &[u8]) -> Result<(), AdapterError>;
    fn read_physical(&mut self, address: u64, output: &mut [u8]) -> Result<(), AdapterError>;
    fn write_physical(&mut self, address: u64, input: &[u8]) -> Result<(), AdapterError>;
}

#[cfg(any(not(feature = "external-adapter"), test))]
pub struct UnavailableAdapter;

#[cfg(any(not(feature = "external-adapter"), test))]
impl UnavailableAdapter {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(any(not(feature = "external-adapter"), test))]
impl KernelAdapter for UnavailableAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo::unavailable()
    }

    fn open(&mut self, _required: Capabilities) -> Result<(), AdapterError> {
        Err(AdapterError::Unavailable)
    }

    fn close(&mut self) -> Result<(), AdapterError> {
        Ok(())
    }

    fn read_kernel(&mut self, _address: u64, _output: &mut [u8]) -> Result<(), AdapterError> {
        Err(AdapterError::Unavailable)
    }

    fn write_kernel(&mut self, _address: u64, _input: &[u8]) -> Result<(), AdapterError> {
        Err(AdapterError::Unavailable)
    }

    fn read_physical(&mut self, _address: u64, _output: &mut [u8]) -> Result<(), AdapterError> {
        Err(AdapterError::Unavailable)
    }

    fn write_physical(&mut self, _address: u64, _input: &[u8]) -> Result<(), AdapterError> {
        Err(AdapterError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_info() -> AdapterInfo {
        AdapterInfo {
            name: "fixture",
            contract_version: CONTRACT_VERSION,
            capabilities: Capabilities::from_bits(
                Capability::KernelRead as u32 | Capability::KernelWrite as u32,
            ),
            max_transfer: MAX_TRANSFER_LIMIT,
            kernel_alignment: 1,
            physical_alignment: 1,
            max_single_write: 8,
            write_semantics: WriteSemantics::REQUIRED,
        }
    }

    #[test]
    fn accepts_exact_read_write_contract() {
        let required =
            Capabilities::from_bits(Capability::KernelRead as u32 | Capability::KernelWrite as u32);

        assert_eq!(valid_info().validate(required, 8), Ok(()));
    }

    #[test]
    fn rejects_missing_write_guarantees() {
        let mut info = valid_info();
        info.write_semantics = WriteSemantics::NONE;

        assert_eq!(
            info.validate(Capabilities::from_bits(Capability::KernelWrite as u32), 1),
            Err(AdapterError::WriteSemantics)
        );
    }

    #[test]
    fn rejects_oversized_write() {
        assert_eq!(
            valid_info().validate(Capabilities::from_bits(Capability::KernelWrite as u32), 9,),
            Err(AdapterError::WriteLimit)
        );
    }
}
