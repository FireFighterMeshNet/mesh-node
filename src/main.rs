#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![no_std]
#![no_main]

// extern crate alloc;

use core::{
    net::{Ipv4Addr, SocketAddrV4},
    str,
};
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Address, Ipv4Cidr, Runner, StackResources, StaticConfigV4,
};
use embassy_time::{Duration, Instant, Timer, WithTimeout};
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
    wifi::{Configuration, WifiApDevice, WifiController, WifiDevice, WifiEvent, WifiStaDevice},
};
use rand::{rngs::SmallRng, Rng as _, SeedableRng as _};

/// Unsorted utilities.
#[macro_use]
pub mod util;

/// Build time generated constants.
mod consts {
    include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

    /// SSID shared between all nodes in mesh.
    pub const SSID: &'static str = if let Some(x) = option_env!("SSID") {
        x
    } else {
        "esp-mesh-default-ssid"
    };
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
async fn ap_task(mut runner: Runner<'static, WifiDevice<'static, WifiApDevice>>) {
    runner.run().await
}

/// Run the STA network stack so the WifiSta responds to network events.
#[embassy_executor::task]
async fn sta_task(mut runner: Runner<'static, WifiDevice<'static, WifiStaDevice>>) {
    runner.run().await
}

/// Handle wifi (both AP and STA).
#[embassy_executor::task]
async fn connection(
    mut controller: WifiController<'static>,
    sta_socket: &'static mut TcpSocket<'static>,
) {
    // Setup initial configuration
    // Configuration can also be changed after start if it needs to.
    // Access point with a password is not supported yet by `esp-wifi` see <https://github.com/esp-rs/esp-wifi-sys/issues/471>.
    let ap_conf = esp_wifi::wifi::AccessPointConfiguration {
        ssid: consts::SSID.try_into().unwrap(),
        ssid_hidden: true,
        ..Default::default()
    };
    let sta_conf = esp_wifi::wifi::ClientConfiguration {
        ssid: consts::SSID.try_into().unwrap(),
        auth_method: esp_wifi::wifi::AuthMethod::None,
        // password: env!("STA_PASSWORD").try_into().unwrap(),
        ..Default::default()
    };
    let mut conf = Configuration::Mixed(sta_conf, ap_conf);
    controller.set_configuration(&conf).unwrap();

    log::info!("Starting WIFI");
    controller.start().await.unwrap();
    log::info!("Started WIFI");
    let scan_res = controller
        .scan_with_config::<2>(esp_wifi::wifi::ScanConfig {
            ssid: Some(consts::SSID),
            show_hidden: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .0;
    dbg!(&scan_res);
    if let Some(other_node) = scan_res.first() {
        conf.as_mixed_conf_mut().0.bssid = Some(other_node.bssid);
        controller.set_configuration(&conf).unwrap();
        const EXP: u32 = 14;
        let buf = make_static!(
            [u8; 2usize.pow(EXP)],
            core::array::from_fn::<_, { 2usize.pow(EXP) }, _>(|i| i as u8)
        );
        for _ in 0..10 {
            match controller.connect().await {
                Ok(()) => {
                    log::info!("connected to node");
                    Timer::after_secs(2).await;
                    err!(
                        sta_socket
                            .connect(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 1), 8000))
                            .await
                    );
                    let instant1 = Instant::now();
                    for _ in 0..100 {
                        err!(sta_socket.write_all(&*buf).await);
                    }
                    log::info!(
                        "100x {} bytes per {}ms",
                        2usize.pow(EXP),
                        instant1.elapsed().as_millis()
                    );
                    err!(sta_socket.write_all(b"\r\n\r\n").await);
                    let mut buf = [0u8; 1024];
                    err!(sta_socket.read(&mut buf).await);
                    let received = str::from_utf8(&buf).unwrap();
                    log::info!("{received}");

                    break;
                }
                e @ Err(_) => err!(e),
            }
        }
    } else {
        log::warn!("other node not found");
    }
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
        controller
            .wait_for_events((WifiEvent::ApStart | WifiEvent::ApStop).into(), false)
            .await;

        match esp_wifi::wifi::get_ap_state() {
            esp_wifi::wifi::WifiState::ApStarted => log::info!("AP started"),
            esp_wifi::wifi::WifiState::ApStopped => log::info!("AP stopped"),
            esp_wifi::wifi::WifiState::Invalid => panic!("invalid wifi state"),
            _ => (),
        }
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

        let mut buffer = [0u8; 2usize.pow(14)];
        log::info!("read loop");
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    log::info!("EOF");
                    break;
                }
                Ok(len) => {
                    // let received = str::from_utf8(&buffer[0..len]).unwrap();
                    log::info!("read {}, {:?}", len, &buffer[0..4]);
                    if buffer
                        .chunks_exact(4)
                        .filter(|x| x == b"\r\r\n\n")
                        .next()
                        .is_some()
                    {
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
        err!(socket.flush().await);
        log::info!("Flushed and closed");
        socket.abort();
        err!(socket.flush().await);
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
    esp_println::logger::init_logger_from_env();
    esp_hal_embassy::init(&clocks, timer.timer0);
    let mut rng = Rng::new(peripherals.RNG);
    let mut prng = {
        if let Some(seed) = consts::RNG_SEED {
            SmallRng::seed_from_u64(seed)
        } else {
            let mut buf = [0u8; 16];
            rng.read(&mut buf);
            SmallRng::from_seed(buf)
        }
    };

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
    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_interface,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, 1), 24),
            gateway: Some(Ipv4Address::new(192, 168, 2, 1)),
            dns_servers: Default::default(),
        }),
        make_static!(StackResources::<3>, StackResources::<3>::new()),
        prng.gen(),
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_interface,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, 53), 24),
            gateway: Some(Ipv4Address::new(192, 168, 2, 1)),
            dns_servers: Default::default(),
        }),
        make_static!(StackResources::<3>, StackResources::<3>::new()),
        prng.gen(),
    );

    spawn.must_spawn(ap_task(ap_runner));
    spawn.must_spawn(sta_task(sta_runner));
    {
        let sta_socket = make_static!(
            TcpSocket<'static>,
            TcpSocket::new(
                sta_stack,
                make_static!([u8; 2usize.pow(12)], [0; 2usize.pow(12)]),
                make_static!([u8; 2usize.pow(14)], [0; 2usize.pow(14)])
            )
        );
        sta_socket.set_timeout(Some(Duration::from_secs(10)));
        spawn.must_spawn(connection(controller, sta_socket));
    }
    spawn.must_spawn(boot_button_reply(io.pins.gpio0));

    // Wait for AP stack to finish startup.
    ap_stack
        .wait_link_up()
        .with_timeout(Duration::from_secs(5))
        .await
        .expect("ap up");

    // Give up on sta after enough tries. Probably failed to connect because of password or the target ssid is missing.
    err!(
        sta_stack
            .wait_link_up()
            .with_timeout(Duration::from_secs(5))
            .await
    );

    // Start TcpSockets for both stacks.
    let ap_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            ap_stack,
            make_static!([u8; 2usize.pow(13)], [0; 2usize.pow(13)]),
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
