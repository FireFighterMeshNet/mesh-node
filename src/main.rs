#![no_std]
#![no_main]

extern crate alloc;

use alloc::{vec, vec::Vec};
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    delay::Delay,
    gpio::{Input, Io},
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    system::SystemControl,
    timer::timg::TimerGroup,
};
use esp_println::dbg;
use esp_wifi::{self, wifi::WifiStaDevice};

#[entry]
fn main() -> ! {
    // Provides #[global_allocator] with given number of bytes.
    // Bigger value here means smaller space left for stack.
    esp_alloc::heap_allocator!(1024);

    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);

    let clocks = ClockControl::max(system.clock_control).freeze();
    let delay = Delay::new(&clocks);

    let wifi = peripherals.WIFI;
    let timer = TimerGroup::new(peripherals.TIMG0, &clocks);
    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Wifi,
        timer.timer0,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
        &clocks,
    )
    .unwrap();
    let mut storage: [_; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        esp_wifi::wifi::utils::create_network_interface(&init, wifi, WifiStaDevice, &mut storage)
            .unwrap();
    controller.start().unwrap();
    let s = controller.scan_n::<3>();
    dbg!(s);

    esp_println::logger::init_logger_from_env();

    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    let boot_button = Input::new(io.pins.gpio0, esp_hal::gpio::Pull::None);

    let mut v: Vec<u8> = vec![0; 256];
    let mut i = 0;
    loop {
        log::info!("Hello world!");
        if boot_button.is_high() {
            log::info!("hi")
        } else if boot_button.is_low() {
            log::info!("lo")
        }
        log::info!("v: {:?}", v.len());
        delay.delay(50.millis());
        v.push(i);
        i += 1;
    }
}
