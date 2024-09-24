#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![no_std]
#![no_main]

// extern crate alloc;

use core::{future::Future, pin::pin, str};
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4,
};
use embassy_time::{Duration, Timer, WithTimeout};
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

/// Run the AP network stack so the WifiAP responds to network events.
#[embassy_executor::task]
async fn ap_task(stack: &'static Stack<WifiDevice<'static, WifiApDevice>>) {
    stack.run().await
}

/// Run the STA network stack so the WifiSta responds to network events.
#[embassy_executor::task]
async fn sta_task(stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>) {
    stack.run().await
}

/// Handle wifi (both AP and STA).
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    // Setup initial configuration
    // Configuration can also be changed after start if it needs to.
    let ap_conf = esp_wifi::wifi::AccessPointConfiguration {
        ssid: "esp32-test".try_into().unwrap(),
        ..Default::default()
    };
    let sta_conf = esp_wifi::wifi::ClientConfiguration {
        ssid: env!("STA_SSID").try_into().unwrap(),
        password: env!("STA_PASSWORD").try_into().unwrap(),
        ..Default::default()
    };
    let conf = Configuration::Mixed(sta_conf, ap_conf);
    controller.set_configuration(&conf).unwrap();

    log::info!("Starting WIFI");
    controller.start().await.unwrap();
    err!(%controller.connect().await);
    log::info!("Started WIFI");
    let mut state = esp_wifi::wifi::get_ap_state();
    let scan_res = controller.scan_n::<3>().await.unwrap().0;
    dbg!(&scan_res);
    // let mut sniffer = controller.take_sniffer().unwrap();
    // sniffer.set_promiscuous_mode(true).unwrap();
    // sniffer.set_receive_cb(|pkt| {
    //     log::info!(
    //         "ty: {:?}, len: {}, data: {:?}",
    //         pkt.frame_type,
    //         pkt.len,
    //         pkt.data
    //     )
    // });
    loop {
        let new_state = esp_wifi::wifi::get_ap_state();
        if new_state != state {
            state = new_state;
            match esp_wifi::wifi::get_ap_state() {
                esp_wifi::wifi::WifiState::ApStarted => log::info!("AP started"),
                esp_wifi::wifi::WifiState::ApStopped => log::info!("AP stopped"),
                esp_wifi::wifi::WifiState::Invalid => panic!("invalid wifi state"),
                _ => (),
            }
        }
        Timer::after_secs(2).await;
    }
}

/// Answer all tcp requests on port 8000 with some basic html.
#[embassy_executor::task(pool_size = 2)]
async fn reply_with_html(socket: &'static mut TcpSocket<'static>) {
    loop {
        log::info!("Waiting for connection...");
        err!(
            socket
                .accept(IpListenEndpoint {
                    addr: None,
                    port: 8000,
                })
                .await
        );
        log::info!(
            "Connected: state: {}, local: {:?}, remote: {:?}",
            socket.state(),
            socket.local_endpoint(),
            socket.remote_endpoint()
        );

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
                e @ Err(_) => break err!(e),
            }
        }
        log::info!("Writing...");
        // let r = socket
        //     .write_all(b"HTTP/1.0 411 Length Required\r\nContent-Length: 0\r\n\r\n")
        //     .await;
        err!(
            socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\n\
                    Content-Length: 44\r\n\r\n\
                    <html><body><h1>Hi! From ESP32</body></html>",
                )
                .await
        );
        log::info!("Flushing with close ...");
        socket.close();
        err!({
            let mut fut = pin!(socket.flush());
            core::future::poll_fn(move |cx| {
                fut.as_ref();
                log::info!("flush poll");
                fut.as_mut().poll(cx)
            })
            .with_timeout(Duration::from_secs(10))
            .await
        });
        log::info!("Flushed and closed");
        socket.abort();
        err!(socket.flush().with_timeout(Duration::from_secs(10)).await);
    }
}

#[esp_hal_embassy::main]
async fn main(spawn: embassy_executor::Spawner) {
    // Provides #[global_allocator] with given number of bytes.
    // Bigger value here means smaller space left for stack.
    // esp_alloc::heap_allocator!(2usize.pow(11));

    // Setup and configuration.
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();
    let timer = TimerGroup::new(peripherals.TIMG0, &clocks);
    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);
    let rng_seed = build_consts::RNG_SEED.unwrap_or({
        let mut buf = [0u8; 8];
        rng.read(&mut buf);
        u64::from_ne_bytes(buf)
    });
    esp_println::logger::init_logger_from_env();
    esp_hal_embassy::init(&clocks, timer.timer0);

    // Setup wifi.
    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Wifi,
        timer.timer1,
        rng,
        peripherals.RADIO_CLK,
        &clocks,
    )
    .unwrap();
    let wifi = peripherals.WIFI;
    let (wifi_ap_interface, wifi_sta_interface, controller) =
        esp_wifi::wifi::new_ap_sta(&init, wifi).unwrap();
    let ap_stack = make_static!(
        Stack<WifiDevice<'_, WifiApDevice>>,
        Stack::new(
            wifi_ap_interface,
            embassy_net::Config::ipv4_static(StaticConfigV4 {
                address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, 1), 24),
                gateway: Some(Ipv4Address::new(192, 168, 2, 1)),
                dns_servers: Default::default(),
            }),
            make_static!(StackResources::<3>, StackResources::<3>::new()),
            rng_seed
        )
    );
    let sta_stack = make_static!(
        Stack<WifiDevice<'_, WifiStaDevice>>,
        Stack::new(
            wifi_sta_interface,
            embassy_net::Config::ipv4_static(StaticConfigV4 {
                address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 0, 53), 24),
                gateway: Some(Ipv4Address::new(192, 168, 0, 1)),
                dns_servers: Default::default(),
            }),
            make_static!(StackResources::<3>, StackResources::<3>::new()),
            rng_seed
        )
    );

    spawn.must_spawn(ap_task(ap_stack));
    spawn.must_spawn(sta_task(sta_stack));
    spawn.must_spawn(connection(controller));
    spawn.must_spawn(boot_button_reply(io.pins.gpio0));

    // Wait for both stacks to finish startup.
    loop {
        if ap_stack.is_link_up() {
            break;
        }
        Timer::after_millis(500).await;
    }
    // Give up on sta after enough tries. Probably failed to connect because of password or the target ssid is missing.
    for _ in 0..5 {
        if dbg!(sta_stack.is_link_up()) {
            break;
        }
        Timer::after_millis(500).await;
    }

    // Start TcpSockets for both stacks.
    let ap_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            ap_stack,
            make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)])
        )
    );
    ap_socket.set_timeout(Some(Duration::from_secs(10)));
    let sta_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            sta_stack,
            make_static!([u8; 2usize.pow(12)], [0; 2usize.pow(12)]),
            make_static!([u8; 2usize.pow(12)], [0; 2usize.pow(12)])
        )
    );
    sta_socket.set_timeout(Some(Duration::from_secs(10)));

    spawn.must_spawn(reply_with_html(ap_socket));
    spawn.must_spawn(reply_with_html(sta_socket));
}
