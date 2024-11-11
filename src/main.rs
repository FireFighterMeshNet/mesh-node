#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![feature(closure_lifetime_binder)] // for<'a> |&'a| syntax
#![feature(async_closure)] // async || syntax
#![no_std]
#![no_main]
#![expect(dead_code)] // Silence errors while prototyping.

// extern crate alloc;

use core::{sync::atomic::AtomicU8, u8};
use embassy_net::{tcp::TcpSocket, IpEndpoint, Runner, StackResources, StaticConfigV4};
use embassy_sync::{channel::Channel, pubsub::PubSubChannel};
use embassy_time::{Duration, Instant, WithTimeout};
use esp_backtrace as _;
use esp_hal::{
    gpio::{GpioPin, Input, Io},
    rng::Rng,
    timer::timg::TimerGroup,
};
use esp_wifi::{
    self,
    wifi::{
        Configuration, PromiscuousPkt, WifiApDevice, WifiController, WifiDevice, WifiError,
        WifiStaDevice,
    },
};
use ieee80211::mac_parser::MACAddress;
use mesh_algo::{controller_task, Packet};
use rand::{rngs::SmallRng, Rng as _, SeedableRng as _};
use util::UnwrapExt;

type Mutex<T> = esp_hal::xtensa_lx::mutex::SpinLockMutex<T>;

/// Unsorted utilities.
#[macro_use]
mod util;
mod mesh_algo;

mod consts {
    use embassy_net::{Ipv4Address, Ipv4Cidr};
    use ieee80211::mac_parser::MACAddress;

    include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

    /// SSID shared between all nodes in mesh.
    pub const SSID: &'static str = if let Some(x) = option_env!("SSID") {
        x
    } else {
        "esp-mesh-default-ssid"
    };

    /// One of Espressif's OUIs taken from <https://standards-oui.ieee.org/>
    pub const ESPRESSIF_OUI: &'static [u8] = [0x10, 0x06, 0x1C].as_slice();

    /// Maximum number of nodes supported in the network at once.
    pub const MAX_NODES: usize = 5;

    /// Protocol version.
    pub const PROT_VERSION: u8 = 0;

    /// CIDR used for gateway (AP).
    pub const AP_CIDR: Ipv4Cidr = Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, 1), 24);

    /// Port used
    pub const PORT: u16 = 8000;

    // `MACAddress` of the root node
    // TODO: pick this or TreeLevel == Some(0) as unique method of determining root.
    pub const ROOT_MAC: MACAddress = MACAddress(ROOT_MAC_ARR);
}
mod config {
    use crate::consts::*;
    use embassy_net::{Ipv4Address, Ipv4Cidr};
    use ieee80211::mac_parser::MACAddress;

    /// UUID from MAC. This crate currently uses the AP MAC as canonical per node (i.e. not the sta interface's mac).
    pub fn uuid_from_mac(mac: MACAddress) -> Option<u8> {
        MAC_TO_UUID.get(&mac.0).map(|x| *x)
    }
    /// STA ip used by the node's STA interface based on its UUID.
    pub fn sta_cidr_from_uuid(uuid: u8) -> Ipv4Cidr {
        Ipv4Cidr::new(Ipv4Address::new(192, 168, 2, uuid + 1), 24)
    }
    /// `Ipv4Cidr` from `MACAddress`
    pub fn sta_cidr_from_mac(mac: MACAddress) -> Option<Ipv4Cidr> {
        uuid_from_mac(mac).map(|mac| sta_cidr_from_uuid(mac))
    }
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
    mesh_algo::sniffer_callback(pkt);

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

/// Try `retries` times to connect.
async fn connect_to_other_node(
    config: &mut Configuration,
    controller: &mut WifiController<'static>,
    bssid: MACAddress,
    retries: usize,
) -> Result<(), WifiError> {
    if config.as_mixed_conf_mut().0.bssid == Some(bssid.0)
        && matches!(controller.is_connected(), Ok(true))
    {
        log::warn!(
            "try connect to {} but already connected",
            MACAddress(config.as_mixed_conf_mut().0.bssid.unwrap())
        );
        return Ok(());
    }

    config.as_mixed_conf_mut().0.bssid = Some(bssid.0);
    controller.set_configuration(&config).unwrap();

    futures_lite::future::poll_once(controller.disconnect())
        .await
        .unwrap_or_log("disconnect unfinished");

    let mut res = Ok(());
    for _ in 0..retries {
        res = controller.connect().await;
        if res.is_ok() {
            break;
        }
    }
    res
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
        ssid: consts::SSID.try_into().unwrap(),
        ssid_hidden: true, // Hidden just means the ssid field is empty (transmitted with length 0) in the default beacons.
        ..Default::default()
    };
    let sta_conf = esp_wifi::wifi::ClientConfiguration {
        ssid: consts::SSID.try_into().unwrap(),
        auth_method: esp_wifi::wifi::AuthMethod::None,
        // password: env!("STA_PASSWORD").try_into().unwrap(),
        ..Default::default()
    };
    let config = Configuration::Mixed(sta_conf, ap_conf);
    controller.set_configuration(&config).unwrap();
    controller.start().await.unwrap();
    log::info!("Started WIFI");

    let mut sniffer = controller.take_sniffer().expect("take sniffer once");
    sniffer.set_promiscuous_mode(true).unwrap();
    let controller_commands = make_static!(
        Channel::<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            mesh_algo::ControllerCommand,
            10,
        >,
        Channel::new()
    );
    let sta_disconnect = make_static!(
        PubSubChannel::<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            (Instant, MACAddress),
            4,
            1,
            1,
        >,
        PubSubChannel::new()
    );
    let ap_sta_connect = make_static!(
        PubSubChannel::<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            (Instant, MACAddress, mesh_algo::ConnectionChange),
            4,
            1,
            1,
        >,
        PubSubChannel::new()
    );
    // Spawn task that handles all `controller` actions.
    spawn.must_spawn(controller_task(
        config,
        controller,
        controller_commands.receiver(),
        sta_disconnect.dyn_publisher().unwrap(),
        ap_sta_connect.dyn_publisher().unwrap(),
    ));
    // Spawn handler before setting callback to avoid pile-up from callback before spawning handler.
    spawn.must_spawn(mesh_algo::connect_to_next_parent(
        controller_commands.sender(),
        sta_disconnect.dyn_subscriber().unwrap(),
    ));
    sniffer.set_receive_cb(sniffer_callback);
    spawn.must_spawn(mesh_algo::beacon_vendor_tx(sniffer, ap_mac));
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
    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
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
    log::info!("TREE_LEVEL: {:?}", consts::TREE_LEVEL);
    log::info!("DENYLIST_MACS:",);
    for mac in consts::DENYLIST_MACS.into_iter().map(|x| MACAddress(*x)) {
        log::info!("{mac:?}")
    }

    // Setup wifi.
    let init = esp_wifi::init(
        esp_wifi::EspWifiInitFor::Wifi,
        timer.timer1,
        rng,
        peripherals.RADIO_CLK,
    )
    .unwrap();
    let wifi = peripherals.WIFI;
    let (wifi_ap_interface, wifi_sta_interface, controller) =
        esp_wifi::wifi::new_ap_sta(&init, wifi).unwrap();
    let ap_mac = MACAddress(wifi_ap_interface.mac_address());
    // let sta_mac = wifi_sta_interface.mac_address();
    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_interface,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: consts::AP_CIDR,
            gateway: Some(consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(
            StackResources::<{ consts::MAX_NODES * 2 }>,
            StackResources::<{ consts::MAX_NODES * 2 }>::new()
        ),
        prng.gen(),
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_interface,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: config::sta_cidr_from_mac(ap_mac)
                .unwrap_or_else(|| panic!("{} missing from mac2uuid", ap_mac)),
            gateway: Some(consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(StackResources::<3>, StackResources::<3>::new()),
        prng.gen(),
    );

    spawn.must_spawn(ap_task(ap_runner));
    spawn.must_spawn(sta_task(sta_runner));
    spawn.must_spawn(connection(spawn, controller, ap_mac));
    spawn.must_spawn(boot_button_reply(io.pins.gpio0));

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
            spawn.must_spawn(mesh_algo::accept_sta_and_forward(
                rx_socket,
                ap_mac,
                ap_tx_socket,
                sta_tx_socket,
            ));
        };
    }
    forward_socket!(ap_stack);
    forward_socket!(ap_stack);

    if consts::TREE_LEVEL != Some(0) {
        let sta_socket = make_static!(
            TcpSocket<'static>,
            TcpSocket::new(
                sta_stack,
                make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
            )
        );
        sta_socket.set_timeout(Some(Duration::from_secs(10)));

        // DEBUG: connect to the ap and send a packet to a mac.
        #[embassy_executor::task]
        async fn f(mut socket: &'static mut TcpSocket<'static>) {
            if let e @ Err(_) = socket
                .connect(IpEndpoint::new(
                    consts::AP_CIDR.address().into(),
                    consts::PORT,
                ))
                .await
            {
                err!(e);
                return;
            }

            for _ in 0..10 {
                let pkt = Packet::new(consts::ROOT_MAC, b"hello world 123").unwrap();

                log::info!("send");
                if let e @ Err(_) = pkt.send(&mut socket).await {
                    err!(e);
                };
            }
            mesh_algo::socket_force_closed(socket).await;
        }
        spawn.must_spawn(f(sta_socket));
    }
}
