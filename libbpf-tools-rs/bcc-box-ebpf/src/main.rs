#![no_std]
#![no_main]

pub mod opensnoop;
pub mod execsnoop;
pub mod softirqs;
pub mod hardirqs;
pub mod wqlat;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
