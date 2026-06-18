#![no_std]
#![no_main]

pub mod opensnoop;
pub mod execsnoop;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
