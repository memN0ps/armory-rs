//! Exact-profile adapter sessions with one explicit cleanup path.

use crate::{
    adapter::{AdapterError, Capabilities, KernelAdapter},
    bytes::{is_kernel_pointer, read_u64, zero},
    kernel::{KernelContext, KernelError, verify_loaded_kernel},
    modules::{ModuleError, SystemModules},
    profiles::KernelField,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionError {
    pub stage: &'static str,
    pub code: u32,
    pub cleanup_succeeded: bool,
}

impl SessionError {
    const fn new(stage: &'static str, code: u32, cleanup_succeeded: bool) -> Self {
        Self {
            stage,
            code,
            cleanup_succeeded,
        }
    }
}

pub struct KernelSession<'a, A: KernelAdapter> {
    adapter: &'a mut A,
    modules: SystemModules,
    pub kernel: KernelContext,
    pub system_process: u64,
    open: bool,
}

impl<'a, A: KernelAdapter> KernelSession<'a, A> {
    pub fn open(
        adapter: &'a mut A,
        required: Capabilities,
        required_write_bytes: usize,
    ) -> Result<Self, SessionError> {
        let info = adapter.info();

        if let Err(error) = info.validate(required, required_write_bytes) {
            return Err(SessionError::new("adapter-contract", error.code(), true));
        }

        if let Err(error) = adapter.open(required) {
            return Err(SessionError::new("adapter-open", error.code(), true));
        }

        let modules = match SystemModules::query() {
            Ok(modules) => modules,
            Err(error) => return Err(close_after_module_error(adapter, error)),
        };
        let kernel = match verify_loaded_kernel(adapter, &modules) {
            Ok(kernel) => kernel,
            Err(error) => return Err(close_after_kernel_error(adapter, error)),
        };
        let address = kernel
            .base
            .checked_add(kernel.profile.value(KernelField::PsInitialSystemProcessRva) as u64)
            .ok_or_else(|| close_after_error(adapter, "system-process-address", 487))?;
        let mut value = [0_u8; 8];

        if let Err(error) = adapter.read_kernel(address, &mut value) {
            zero(&mut value);
            return Err(close_after_adapter_error(
                adapter,
                "system-process-read",
                error,
            ));
        }

        let system_process = read_u64(&value, 0).unwrap_or(0);
        zero(&mut value);

        if !is_kernel_pointer(system_process) {
            return Err(close_after_error(adapter, "system-process-value", 13));
        }

        Ok(Self {
            adapter,
            modules,
            kernel,
            system_process,
            open: true,
        })
    }

    pub fn adapter(&mut self) -> &mut A {
        self.adapter
    }

    pub fn parts(&mut self) -> (&mut A, &SystemModules, KernelContext, u64) {
        (
            self.adapter,
            &self.modules,
            self.kernel,
            self.system_process,
        )
    }

    pub fn close(mut self) -> Result<(), AdapterError> {
        let result = self.adapter.close();
        self.open = false;

        result
    }
}

impl<A: KernelAdapter> Drop for KernelSession<'_, A> {
    fn drop(&mut self) {
        if self.open {
            let _ = self.adapter.close();
            self.open = false;
        }
    }
}

fn close_after_module_error<A: KernelAdapter>(adapter: &mut A, error: ModuleError) -> SessionError {
    let cleanup_succeeded = adapter.close().is_ok();

    SessionError::new(error.stage(), error.code(), cleanup_succeeded)
}

fn close_after_kernel_error<A: KernelAdapter>(adapter: &mut A, error: KernelError) -> SessionError {
    let cleanup_succeeded = adapter.close().is_ok();

    SessionError::new(error.stage(), error.code(), cleanup_succeeded)
}

fn close_after_adapter_error<A: KernelAdapter>(
    adapter: &mut A,
    stage: &'static str,
    error: AdapterError,
) -> SessionError {
    close_after_error(adapter, stage, error.code())
}

fn close_after_error<A: KernelAdapter>(
    adapter: &mut A,
    stage: &'static str,
    code: u32,
) -> SessionError {
    let cleanup_succeeded = adapter.close().is_ok();

    SessionError::new(stage, code, cleanup_succeeded)
}
