#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![no_std]
#![no_main]

// extern crate alloc;

use core::str;
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4,
};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    gpio::{GpioPin, Input, Io},
    peripherals::Peripherals,
    rng::Rng,
    system::SystemControl,
    timer::timg::TimerGroup,
};
use esp_println::dbg;
use esp_wifi::{
    self,
    wifi::{Configuration, WifiApDevice, WifiController, WifiDevice, WifiStaDevice},
};

/// Unsorted utilities.
#[macro_use]
pub mod util;

/// Build time generated constants.
mod build_consts {
    include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));
}

/// Display a message when the button is pressed to confirm the device is still responsive.
#[embassy_executor::task]
async fn boot_button_reply(gpio0: GpioPin<0>) {
    let mut boot_button = Input::new(gpio0, esp_hal::gpio::Pull::None);

    let mut i = 0u8;
    loop {
        boot_button.wait_for_falling_edge().await;
        log::info!("I'm still alive! {i}");
        i = i.wrapping_add(1);
    }
}

/// Run the network stack so the WifiAP responds to network events.
#[embassy_executor::task]
async fn net_task(stack: &'static Stack<WifiDevice<'static, WifiApDevice>>) {
    stack.run().await
}

/// Handle setting up the AP.
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    // Setup initial AP point:
    let conf = Configuration::AccessPoint(esp_wifi::wifi::AccessPointConfiguration {
        ssid: "esp32-test".try_into().unwrap(),
        ..Default::default()
    });
    controller.set_configuration(&conf).unwrap();
    log::info!("Starting WIFI AP");
    controller.start().await.unwrap();
    log::info!("Started WIFI AP");
    let mut state = esp_wifi::wifi::get_ap_state();
    let scan_res = controller.scan_n::<3>().await.unwrap().0;
    dbg!(&scan_res);
    loop {
        let new_state = esp_wifi::wifi::get_ap_state();
        if new_state != state {
            state = new_state;
            match esp_wifi::wifi::get_ap_state() {
                esp_wifi::wifi::WifiState::ApStarted => log::info!("started"),
                esp_wifi::wifi::WifiState::ApStopped => log::info!("stopped"),
                esp_wifi::wifi::WifiState::Invalid => panic!("invalid wifi state"),
                _ => (),
            }
        }
        Timer::after_secs(2).await;
    }
}

#[esp_hal_embassy::main]
async fn main(spawn: embassy_executor::Spawner) -> ! {
    // Provides #[global_allocator] with given number of bytes.
    // Bigger value here means smaller space left for stack.
    // Only needed if we actually allocate stuff on the heap.
    // esp_alloc::heap_allocator!(1024);

    // Setup and configuration.
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();
    let timer = TimerGroup::new(peripherals.TIMG0, &clocks);
    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    esp_println::logger::init_logger_from_env();
    esp_hal_embassy::init(&clocks, timer.timer0);

    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Wifi,
        timer.timer1,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
        &clocks,
    )
    .unwrap();
    let wifi = peripherals.WIFI;
    let (wifi_ap_interface, wifi_sta_interface, controller) =
        esp_wifi::wifi::new_ap_sta(&init, wifi).unwrap();
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, 1), 24),
        gateway: Some(Ipv4Address::new(192, 168, 2, 1)),
        dns_servers: Default::default(),
    });
    let stack = make_static!(
        Stack<WifiDevice<'_, WifiApDevice>>,
        Stack::new(
            wifi_ap_interface,
            config,
            make_static!(StackResources::<3>, StackResources::<3>::new()),
            build_consts::RNG_SEED
        )
    );

    spawn.must_spawn(net_task(stack));
    spawn.must_spawn(connection(controller));
    spawn.must_spawn(boot_button_reply(io.pins.gpio0));

    let mut rx_buffer = [0; 2usize.pow(10)];
    let mut tx_buffer = [0; 2usize.pow(10)];

    loop {
        if dbg!(stack.is_link_up()) {
            break;
        }
        Timer::after_millis(500).await;
    }

    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(10)));
    loop {
        log::info!("Waiting for connection...");
        let r = socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 8000,
            })
            .await;
        log::info!(
            "Connected: state: {}, local: {:?}, remote: {:?}",
            socket.state(),
            socket.local_endpoint(),
            socket.remote_endpoint()
        );
        err!(r);

        let mut buffer = [0u8; 2usize.pow(10)];
        loop {
            log::info!("read loop");
            match dbg!(socket.read(&mut buffer).await) {
                Ok(0) => {
                    log::info!("EOF");
                    break;
                }
                Ok(len) => {
                    let received = str::from_utf8(&buffer[0..len]).unwrap();
                    log::info!("read {} bytes of: {}", len, received);
                    if received.contains("\r\n\r\n") {
                        break;
                    }
                }
                e @ Err(_) => err!(e),
            }
        }
        log::info!("Writing...");
        // let r = socket
        //     .write_all(b"HTTP/1.0 411 Length Required\r\nContent-Length: 0\r\n\r\n")
        //     .await;
        let r = socket
            .write_all(
                b"HTTP/1.0 200 OK\r\n\
                Content-Length: 44\r\n\r\n\
                <html><body><h1>Hi! From ESP32</body></html>",
            )
            .await;
        err!(r);
        log::info!("Flushing...");
        let r = socket.flush().await;
        log::info!("Flushed and closing");
        err!(r);
        socket.close();
        let r = socket.flush().await;
        err!(r);
        socket.abort();
        let r = socket.flush().await;
        err!(r);
    }

    loop {
        Timer::after(Duration::MAX).await;
    }
}
