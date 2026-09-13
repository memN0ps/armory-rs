//! Driver-agnostic Windows kernel research BOF.

#![no_std]

mod adapter;
#[cfg(all(feature = "external-adapter", not(test)))]
mod adapter_external;
mod args;
mod bytes;
mod callback;
mod command;
mod credential_crypto;
mod credential_packages;
mod credentials;
mod dse;
mod etw_ti;
mod heap;
mod image_scan;
mod kernel;
mod memory;
mod minifilter;
mod modules;
mod object_callback;
mod output;
mod platform;
mod ppl;
mod process;
mod process_control;
#[allow(dead_code)]
mod profiles;
mod recovery;
mod registry_callback;
mod session;
mod system_image;
mod token;
mod token_control;
mod user_module;
mod virtual_memory;
mod wdigest;

#[cfg(any(not(feature = "external-adapter"), test))]
use adapter::UnavailableAdapter as ActiveAdapter;
#[cfg(all(feature = "external-adapter", not(test)))]
use adapter_external::ExternalAdapter as ActiveAdapter;
use args::Arguments;
use command::Command;
use output::Output;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(export_name = "go")]
pub extern "C" fn entry(buffer: *const u8, length: i32) {
    let mut output = Output::new();
    let mut adapter = ActiveAdapter::new();

    let arguments = match Arguments::new(buffer, length) {
        Ok(arguments) => arguments,
        Err(error) => {
            output.error(error.message());
            command::print_usage(&mut output);
            output.flush();
            return;
        }
    };

    match Command::parse(arguments) {
        Ok(command) => command.run(&mut adapter, &mut output),
        Err(error) => {
            output.error(error.message());
            command::print_usage(&mut output);
        }
    }

    output.flush();
}
