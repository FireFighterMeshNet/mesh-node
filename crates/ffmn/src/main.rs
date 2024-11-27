#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![feature(closure_lifetime_binder)] // for<'a> |&'a| syntax
#![feature(async_closure)] // async || syntax
#![no_std]
#![no_main]

// extern crate alloc;

mod esp32_imp;

use common::*;
use core::{sync::atomic::AtomicU8, u8};
use embassy_net::{tcp::TcpSocket, Runner, StackResources, StaticConfigV6};
use embassy_time::{Duration, Timer, WithTimeout};
use esp32_imp::{EspSimulator, SnifferWrapper};
use esp_backtrace as _;
use esp_hal::{
    gpio::{GpioPin, Input},
    macros::handler,
    peripherals::TIMG0,
    rng::Rng,
    timer::timg::{TimerGroup, Wdt},
    InterruptConfigurable,
};
use esp_wifi::{
    self,
    wifi::{
        Configuration, PromiscuousPkt, WifiApDevice, WifiController, WifiDevice, WifiStaDevice,
    },
    EspWifiController,
};
use ieee80211::mac_parser::MACAddress;
use rand::{rngs::SmallRng, Rng as _, SeedableRng as _};
use tree_mesh::{simulator::Simulator, Packet};

tree_mesh::define_monomorphized_tasks! {EspSimulator}

mod consts {
    use ieee80211::mac_parser::MACAddress;

    include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

    // `MACAddress` of the root node
    // TODO: pick this or TreeLevel == Some(0) as unique method of determining root.
    pub const ROOT_MAC: MACAddress = MACAddress(ROOT_MAC_ARR);
}

/// Display a message when the button is pressed to confirm the device is still responsive.
#[embassy_executor::task]
async fn boot_button_reply(gpio0: GpioPin<0>) -> ! {
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
async fn ap_task(mut runner: Runner<'static, WifiDevice<'static, WifiApDevice>>) -> ! {
    runner.run().await
}

/// Run the STA network stack so the WifiSta responds to network events.
#[embassy_executor::task]
async fn sta_task(mut runner: Runner<'static, WifiDevice<'static, WifiStaDevice>>) -> ! {
    runner.run().await
}

/// Output packet's data as expected by the wifi-shark extcap at `INFO` level.
fn log_packet(pkt: &PromiscuousPkt) {
    #[inline]
    fn log_packet_data(data: &[u8]) {
        if cfg!(feature = "dump-packets") {
            log::info!("@WIFIRAWFRAME {:?}", data)
        }
    }
    // The last 4 bytes are the frame check sequence, which wireshark doesn't check and we don't care about.
    log_packet_data(&pkt.data[..pkt.data.len().saturating_sub(4)]);
}

/// The callback for any detected packet.
pub fn sniffer_callback(pkt: PromiscuousPkt) {
    let pkt = &pkt;
    tree_mesh::sniffer_callback::<esp32_imp::EspSimulator>(&pkt.data);

    // Only log some of packets to avoid overload.
    // Otherwise the network stack starts failing because logging takes too long.
    static CNT: AtomicU8 = AtomicU8::new(0);
    let cnt = CNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if cnt == 0 {
        log_packet(pkt);
    } else {
        CNT.store(
            (cnt + 1).rem_euclid(110),
            core::sync::atomic::Ordering::SeqCst,
        );
    }
}

/// Handle wifi (both AP and STA).
#[embassy_executor::task]
async fn connection(
    spawn: embassy_executor::Spawner,
    mut controller: WifiController<'static>,
    ap_mac: MACAddress,
) {
    // Setup initial configuration
    // Configuration can also be changed after start if it needs to.
    // Access point with a password is not supported yet by `esp-wifi` see <https://github.com/esp-rs/esp-hal/issues/1610>.
    // Though apparently "WPA2-Enterprise" is? <https://github.com/esp-rs/esp-hal/issues/1608>
    // So maybe we'll use that?
    let ap_conf = esp_wifi::wifi::AccessPointConfiguration {
        ssid: tree_mesh::consts::SSID.try_into().unwrap(),
        ssid_hidden: true, // Hidden just means the ssid field is empty (transmitted with length 0) in the default beacons.
        ..Default::default()
    };
    let sta_conf = esp_wifi::wifi::ClientConfiguration {
        ssid: tree_mesh::consts::SSID.try_into().unwrap(),
        auth_method: esp_wifi::wifi::AuthMethod::None,
        // password: env!("STA_PASSWORD").try_into().unwrap(),
        ..Default::default()
    };
    let config = Configuration::Mixed(sta_conf, ap_conf);
    controller.set_configuration(&config).unwrap();
    controller.start_async().await.unwrap();
    log::info!("Started WIFI");

    let mut sniffer = controller.take_sniffer().expect("take sniffer once");
    sniffer.set_promiscuous_mode(true).unwrap();

    let controller = make_static!(
        tree_mesh::AsyncMutex<WifiController<'static>>,
        tree_mesh::AsyncMutex::new(controller)
    );

    // Connect to identified parents if not root.
    if consts::TREE_LEVEL != Some(0) {
        spawn.must_spawn(__connect_to_next_parent_monomorph(controller));
    }
    sniffer.set_receive_cb(sniffer_callback);
    spawn.must_spawn(__beacon_vendor_tx_wrapper_monomorph(
        SnifferWrapper(sniffer),
        ap_mac,
    ));
}

#[handler]
fn print_backtrace() {
    esp_println::println!("Watchdog backtrace:");
    // copied from `esp_backtrace` internals.
    for addr in esp_backtrace::arch::backtrace().into_iter().flatten() {
        esp_println::println!("0x{:x}", addr - 3)
    }
}

/// Setup a watchdog and `feed` it periodically. If this isn't polled frequently enough the `ProCPU` restarts.
#[embassy_executor::task]
async fn feed_wdt() -> ! {
    let mut wdt = Wdt::<TIMG0>::default();
    // TODO: It doesn't seem like the interrupt is actually called.
    // Fortunately, the default handler for `Wdt` (not RTC) watchdogs seems to print a line from the stacktrace.
    // It would be nice if this worked, though.
    wdt.set_interrupt_handler(print_backtrace);
    wdt.enable();
    // Note: This doesn't seem to do anything when less than 380000us
    wdt.set_timeout(
        esp_hal::timer::timg::MwdtStage::Stage0,
        esp_hal::delay::MicrosDurationU64::secs(5),
    );
    loop {
        wdt.feed();
        // 1 second leeway on watchdog timeout.
        Timer::after_secs(4).await;
    }
}

#[esp_hal_embassy::main]
async fn main(spawn: embassy_executor::Spawner) {
    // Provides #[global_allocator] with given number of bytes.
    // Bigger value here means smaller space left for stack.
    // `esp-wifi` recommends at least `92k` for `coex` and `72k` for wifi.
    esp_alloc::heap_allocator!(72_000);

    // Setup and configuration.
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let timer = TimerGroup::new(peripherals.TIMG0);
    esp_println::logger::init_logger_from_env();
    esp_hal_embassy::init(timer.timer0);
    let mut rng = Rng::new(peripherals.RNG);
    let mut prng = if let Some(seed) = consts::RNG_SEED {
        SmallRng::seed_from_u64(seed)
    } else {
        let mut buf = [0u8; 16];
        rng.read(&mut buf);
        SmallRng::from_seed(buf)
    };
    spawn.must_spawn(feed_wdt());
    log::info!("TREE_LEVEL: {:?}", consts::TREE_LEVEL);
    log::info!("DENYLIST_MACS:",);
    for mac in consts::DENYLIST_MACS.into_iter().map(|x| MACAddress(*x)) {
        log::info!("{mac:?}")
    }

    // Setup wifi.
    let init = make_static!(
        EspWifiController<'static>,
        esp_wifi::init(timer.timer1, rng, peripherals.RADIO_CLK).unwrap()
    );
    let wifi = peripherals.WIFI;
    let (wifi_ap_interface, wifi_sta_interface, controller) =
        esp_wifi::wifi::new_ap_sta(&*init, wifi).unwrap();
    let ap_mac = MACAddress(wifi_ap_interface.mac_address());
    let sta_mac = MACAddress(wifi_sta_interface.mac_address());
    log::info!("ap_mac: {}; sta_mac: {}", ap_mac, sta_mac);
    assert_eq!(EspSimulator::ap_mac_to_sta(ap_mac), sta_mac);
    assert_eq!(EspSimulator::sta_mac_to_ap(sta_mac), ap_mac);

    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_interface,
        embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: tree_mesh::consts::AP_CIDR,
            gateway: Some(tree_mesh::consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>,
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>::new()
        ),
        prng.gen(),
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_interface,
        embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: tree_mesh::consts::sta_cidr_from_mac(ap_mac),
            gateway: Some(tree_mesh::consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>,
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>::new()
        ),
        prng.gen(),
    );

    spawn.must_spawn(ap_task(ap_runner));
    spawn.must_spawn(sta_task(sta_runner));
    spawn.must_spawn(connection(spawn, controller, ap_mac));
    spawn.must_spawn(boot_button_reply(peripherals.GPIO0));

    // Wait for AP stack to finish startup.
    ap_stack
        .wait_link_up()
        .with_timeout(Duration::from_secs(5))
        .await
        .expect("ap up");

    // Start TcpSockets.
    macro_rules! forward_socket {
        ($stack:ident) => {
            let rx_socket = make_static!(
                TcpSocket<'static>,
                TcpSocket::new(
                    $stack,
                    make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                    make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
                )
            );
            let ap_tx_socket = make_static!(
                TcpSocket<'static>,
                TcpSocket::new(
                    ap_stack,
                    make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                    make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
                )
            );
            let sta_tx_socket = make_static!(
                TcpSocket<'static>,
                TcpSocket::new(
                    sta_stack,
                    make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                    make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
                )
            );
            rx_socket.set_timeout(Some(Duration::from_secs(10)));
            ap_tx_socket.set_timeout(Some(Duration::from_secs(10)));
            sta_tx_socket.set_timeout(Some(Duration::from_secs(10)));
            spawn.must_spawn(tree_mesh::accept_sta_and_forward(
                rx_socket,
                ap_mac,
                ap_tx_socket,
                sta_tx_socket,
            ));
        };
    }
    forward_socket!(ap_stack);
    forward_socket!(ap_stack);
    forward_socket!(sta_stack);

    {
        let ap_rx_socket = make_static!(
            TcpSocket<'static>,
            TcpSocket::new(
                ap_stack,
                make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
            )
        );
        let sta_tx_socket = make_static!(
            TcpSocket<'static>,
            TcpSocket::new(
                sta_stack,
                make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
            )
        );

        ap_rx_socket.set_timeout(Some(Duration::from_secs(10)));
        sta_tx_socket.set_timeout(Some(Duration::from_secs(10)));
        spawn.must_spawn(__propagate_neighbors_monomorph(ap_rx_socket, sta_tx_socket));
    }

    let sta_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            sta_stack,
            make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
        )
    );
    sta_socket.set_timeout(Some(Duration::from_secs(10)));
    let ap_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            ap_stack,
            make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
        )
    );
    ap_socket.set_timeout(Some(Duration::from_secs(10)));

    if consts::TREE_LEVEL != Some(0) {
        // DEBUG: connect to the ap and send a packet to a mac.
        #[embassy_executor::task]
        async fn f(
            ap_socket: &'static mut TcpSocket<'static>,
            sta_socket: &'static mut TcpSocket<'static>,
        ) {
            for _ in 0..10 {
                let pkt = Packet::new(consts::ROOT_MAC, b"hello world 123").unwrap();

                log::info!("send");
                if let e @ Err(_) = pkt.send(&mut *ap_socket, &mut *sta_socket).await {
                    err!(e);
                };
            }
            tree_mesh::socket_force_closed(ap_socket).await;
            tree_mesh::socket_force_closed(sta_socket).await;
        }
        spawn.must_spawn(f(ap_socket, sta_socket));
    } else {
        #[embassy_executor::task]
        async fn f(ap_socket: &'static mut TcpSocket<'static>) {
            Timer::after_secs(10).await;
            for _ in 0..10 {
                let pkt = Packet::new(
                    MACAddress([0xc6, 0xdd, 0x57, 0x75, 0xb3, 0x60]),
                    b"hello world 123",
                )
                .unwrap();

                log::info!("send");
                if let e @ Err(_) = pkt.send(&mut *ap_socket, None).await {
                    err!(e);
                };
            }
            tree_mesh::socket_force_closed(ap_socket).await;
        }

        spawn.must_spawn(f(ap_socket));
    }
}
