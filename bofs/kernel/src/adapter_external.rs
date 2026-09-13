//! Generic link boundary for a separately reviewed Rust driver adapter.

use crate::adapter::{AdapterError, AdapterInfo, Capabilities, KernelAdapter, WriteSemantics};

const EXTERNAL_ADAPTER_ABI_VERSION: u32 = 1;

#[repr(C)]
struct AdapterDescriptor {
    structure_size: u32,
    abi_version: u32,
    contract_version: u32,
    capabilities: u32,
    max_transfer: usize,
    kernel_alignment: usize,
    physical_alignment: usize,
    max_single_write: usize,
    write_semantics: u32,
}

unsafe extern "C" {
    fn kernel_adapter_info(descriptor: *mut AdapterDescriptor, descriptor_size: usize) -> u32;
    fn kernel_adapter_open(required_capabilities: u32) -> u32;
    fn kernel_adapter_close() -> u32;
    fn kernel_adapter_read_kernel(address: u64, output: *mut u8, length: usize) -> u32;
    fn kernel_adapter_write_kernel(address: u64, input: *const u8, length: usize) -> u32;
    fn kernel_adapter_read_physical(address: u64, output: *mut u8, length: usize) -> u32;
    fn kernel_adapter_write_physical(address: u64, input: *const u8, length: usize) -> u32;
}

pub struct ExternalAdapter {
    descriptor: AdapterDescriptor,
    information_status: u32,
    open: bool,
}

impl ExternalAdapter {
    pub fn new() -> Self {
        let mut descriptor = AdapterDescriptor::empty();
        let status = unsafe {
            kernel_adapter_info(&mut descriptor, core::mem::size_of::<AdapterDescriptor>())
        };
        let valid_descriptor = descriptor.structure_size as usize
            == core::mem::size_of::<AdapterDescriptor>()
            && descriptor.abi_version == EXTERNAL_ADAPTER_ABI_VERSION;

        if status != 0 || !valid_descriptor {
            descriptor = AdapterDescriptor::empty();
        }

        Self {
            descriptor,
            information_status: if status != 0 {
                status
            } else if valid_descriptor {
                0
            } else {
                13
            },
            open: false,
        }
    }

    fn result(status: u32) -> Result<(), AdapterError> {
        if status == 0 {
            Ok(())
        } else {
            Err(AdapterError::Backend(status))
        }
    }

    fn validate_transfer(&self, address: u64, length: usize) -> Result<(), AdapterError> {
        if !self.open {
            return Err(AdapterError::Unavailable);
        }

        if address == 0 || address.checked_add(length as u64).is_none() {
            return Err(AdapterError::InvalidAddress);
        }

        if length == 0 || length > self.descriptor.max_transfer {
            return Err(AdapterError::InvalidBuffer);
        }

        Ok(())
    }
}

impl KernelAdapter for ExternalAdapter {
    fn info(&self) -> AdapterInfo {
        AdapterInfo {
            name: "external Rust adapter",
            contract_version: self.descriptor.contract_version,
            capabilities: Capabilities::from_bits(self.descriptor.capabilities),
            max_transfer: self.descriptor.max_transfer,
            kernel_alignment: self.descriptor.kernel_alignment,
            physical_alignment: self.descriptor.physical_alignment,
            max_single_write: self.descriptor.max_single_write,
            write_semantics: WriteSemantics::from_bits(self.descriptor.write_semantics),
        }
    }

    fn open(&mut self, required: Capabilities) -> Result<(), AdapterError> {
        if self.information_status != 0 {
            return Err(AdapterError::Backend(self.information_status));
        }

        if self.open {
            return Err(AdapterError::Backend(170));
        }

        Self::result(unsafe { kernel_adapter_open(required.bits()) })?;
        self.open = true;

        Ok(())
    }

    fn close(&mut self) -> Result<(), AdapterError> {
        if !self.open {
            return Ok(());
        }

        let result = Self::result(unsafe { kernel_adapter_close() });
        self.open = false;

        result
    }

    fn read_kernel(&mut self, address: u64, output: &mut [u8]) -> Result<(), AdapterError> {
        self.validate_transfer(address, output.len())?;

        Self::result(unsafe {
            kernel_adapter_read_kernel(address, output.as_mut_ptr(), output.len())
        })
    }

    fn write_kernel(&mut self, address: u64, input: &[u8]) -> Result<(), AdapterError> {
        self.validate_transfer(address, input.len())?;

        if input.len() > self.descriptor.max_single_write {
            return Err(AdapterError::WriteLimit);
        }

        Self::result(unsafe { kernel_adapter_write_kernel(address, input.as_ptr(), input.len()) })
    }

    fn read_physical(&mut self, address: u64, output: &mut [u8]) -> Result<(), AdapterError> {
        self.validate_transfer(address, output.len())?;

        Self::result(unsafe {
            kernel_adapter_read_physical(address, output.as_mut_ptr(), output.len())
        })
    }

    fn write_physical(&mut self, address: u64, input: &[u8]) -> Result<(), AdapterError> {
        self.validate_transfer(address, input.len())?;

        if input.len() > self.descriptor.max_single_write {
            return Err(AdapterError::WriteLimit);
        }

        Self::result(unsafe { kernel_adapter_write_physical(address, input.as_ptr(), input.len()) })
    }
}

impl AdapterDescriptor {
    const fn empty() -> Self {
        Self {
            structure_size: core::mem::size_of::<Self>() as u32,
            abi_version: EXTERNAL_ADAPTER_ABI_VERSION,
            contract_version: 0,
            capabilities: 0,
            max_transfer: 0,
            kernel_alignment: 0,
            physical_alignment: 0,
            max_single_write: 0,
            write_semantics: 0,
        }
    }
}
