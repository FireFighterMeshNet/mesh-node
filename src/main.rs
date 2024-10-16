#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![no_std]
#![no_main]

// extern crate alloc;

use core::{
    borrow::Borrow,
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddrV4},
    str,
    sync::atomic::AtomicU8,
    u8,
};
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Address, Ipv4Cidr, Runner, StackResources, StaticConfigV4,
};
use embassy_time::{Duration, Instant, Timer, WithTimeout};
use embedded_io_async::Write;
use esp_backtrace as _;
use esp_hal::{
    gpio::{GpioPin, Input, Io},
    rng::Rng,
    timer::timg::TimerGroup,
    xtensa_lx::mutex::Mutex as _,
};
use esp_println::dbg;
use esp_wifi::{
    self,
    wifi::{
        Configuration, PromiscuousPkt, Sniffer, WifiApDevice, WifiController, WifiDevice,
        WifiEvent, WifiStaDevice,
    },
};
use heapless::FnvIndexMap;
use ieee80211::{
    common::CapabilitiesInformation,
    element_chain,
    elements::{SSIDElement, VendorSpecificElement},
    mac_parser::MACAddress,
    mgmt_frame::BeaconFrame,
    scroll::Pwrite,
};
use rand::{rngs::SmallRng, Rng as _, SeedableRng as _};
use scroll::Pread;
use util::UnwrapTodo;

type Mutex<T> = esp_hal::xtensa_lx::mutex::SpinLockMutex<T>;

/// Unsorted utilities.
#[macro_use]
pub mod util;

mod consts {
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

    /// Protocol version. Currently unchecked.
    pub const PROT_VERSION: u8 = 0;
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
fn log_packet(data: &[u8]) {
    if cfg!(feature = "dump-packets") {
        log::info!("@WIFIRAWFRAME {:?}", data)
    }
}

/// Periodic transmit of beacon with custom vendor data.
#[embassy_executor::task]
async fn beacon_vendor_tx(mut sniffer: Sniffer, source_mac: MACAddress) {
    // Buffer for beacon body
    let mut beacon = [0u8; 256];
    let data: NodeDataBeaconMsg = STATE.borrow().lock(|table| table.me.borrow().into());
    let length = beacon
        .pwrite(
            BeaconFrame {
                header: ieee80211::mgmt_frame::ManagementFrameHeader {
                    transmitter_address: source_mac,
                    bssid: source_mac,
                    receiver_address: MACAddress([0xff; 6]), // multicast to all
                    ..Default::default()
                },
                body: ieee80211::mgmt_frame::body::BeaconLikeBody {
                    timestamp: 0,
                    beacon_interval: 100,
                    capabilities_info: CapabilitiesInformation::new().with_is_ess(true), // is ess = is ap
                    elements: element_chain! {
                        SSIDElement::new(consts::SSID).unwrap(),
                        VendorSpecificElement::new_prefixed(
                            // Vender specific OUI is first 3 bytes. Rest is payload concatenated.
                            consts::ESPRESSIF_OUI,
                            data,
                        )
                    },
                    _phantom: PhantomData,
                },
            },
            0,
        )
        .unwrap();
    log::info!("sending vendor-beacons");
    loop {
        // Send raw frame using wifi-stack's sequence number.
        // Will give an `ESP_ERR_INVALID_ARG` if sending for most configurations if `use_internal_seq_num` != true when wi-fi is initialized.
        // See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/wifi.html#side-effects-to-avoid-in-different-scenarios>
        if let Err(e) = sniffer.send_raw_frame(false, &beacon[0..length], true) {
            log::error!("Failed to send beacon: {e:?}")
        }

        Timer::after_millis(100).await;
    }
}

#[derive(Debug, Default, Clone)]
enum TreePos {
    /// Above this node in tree.
    Ancestor,
    /// Below this node in tree.
    Descendant,
    /// Same level or below sibling in tree.
    Sibling,
    /// Not connected to this node.
    #[default]
    Disconnected,
}
/// Value of data for a single node.
#[derive(Default, Debug, Clone)]
struct NodeData {
    postion: TreePos,
    /// Version of this protocol the node is running.
    version: u8,
    /// Distance from root. Root is 0. Root's children is 1, etc.
    level: u8,
}
/// Beacon message per node.
#[derive(Debug, Clone)]
struct NodeDataBeaconMsg {
    version: u8,
    level: u8,
}

impl scroll::ctx::TryIntoCtx for NodeDataBeaconMsg {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite_with(self.version, offset, scroll::NETWORK)?;
        dst.gwrite_with(self.level, offset, scroll::NETWORK)?;

        Ok(*offset)
    }
}
impl scroll::ctx::TryFromCtx<'_> for NodeDataBeaconMsg {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let version = from.gread_with(offset, scroll::NETWORK)?;
        let level = from.gread_with(offset, scroll::NETWORK)?;

        Ok((Self { version, level }, *offset))
    }
}
impl scroll::ctx::MeasureWith<()> for NodeDataBeaconMsg {
    fn measure_with(&self, _: &()) -> usize {
        size_of::<Self>()
    }
}
impl From<&NodeDataBeaconMsg> for NodeData {
    fn from(value: &NodeDataBeaconMsg) -> Self {
        Self {
            version: value.version,
            level: value.level,
            ..Default::default()
        }
    }
}
impl From<&NodeData> for NodeDataBeaconMsg {
    fn from(value: &NodeData) -> Self {
        Self {
            version: value.version,
            level: value.level,
        }
    }
}

impl NodeData {
    pub const fn new_disconnected() -> Self {
        NodeData {
            postion: TreePos::Disconnected,
            version: consts::PROT_VERSION,
            level: u8::MAX,
        }
    }
}

/// Table of all mesh info.
#[derive(Debug, Clone)]
struct NodeTable {
    /// Data for this node.
    pub me: NodeData,
    // `FnvIndexMap` has to be a power of two in size.
    /// The data for other nodes.
    pub map: FnvIndexMap<MACAddress, NodeData, { consts::MAX_NODES.next_power_of_two() }>,
}

static STATE: Mutex<NodeTable> = Mutex::new(NodeTable {
    me: {
        let mut out = NodeData::new_disconnected();
        if let Some(level) = consts::TREE_LEVEL {
            out.level = level;
        }
        out
    },
    map: FnvIndexMap::new(),
});

pub fn sniffer_callback(pkt: PromiscuousPkt) {
    let frame = ieee80211::match_frames! {pkt.data, beacon = BeaconFrame => { beacon }};
    match frame {
        Ok(beacon) => {
            if beacon.ssid() == Some(consts::SSID) {
                for field in beacon
                    .elements
                    .get_matching_elements::<ieee80211::elements::VendorSpecificElement>()
                {
                    let Some(payload) = field.get_payload_if_prefix_matches(consts::ESPRESSIF_OUI)
                    else {
                        log::debug!("unmatched beacon field: {:?}", field);
                        continue;
                    };
                    let Ok(data) = payload.pread::<NodeDataBeaconMsg>(0) else {
                        log::warn!("bad beacon field? {:?}", field);
                        continue;
                    };
                    let data = data.borrow().into();
                    STATE
                        .borrow()
                        .lock(|table| table.map.insert(beacon.header.bssid, data))
                        .todo();
                }
            }
        }
        Err(_) => (), // ignore frame type not matched
    }

    // Only log some of packets to avoid overload.
    // Otherwise the network stack starts failing because logging takes too long.
    static CNT: AtomicU8 = AtomicU8::new(0);
    let cnt = CNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if cnt == 0 {
        // log::info!("ty: {:?}, len: {}", pkt.frame_type, pkt.len);
        // The last 4 bytes are the frame check sequence, which wireshark doesn't check and we don't care about.
        log_packet(&pkt.data[..pkt.data.len().saturating_sub(4)]);
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
    sta_socket: &'static mut TcpSocket<'static>,
    ap_mac: MACAddress,
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
        const EXP: u32 = 13;
        let buf = make_static!(
            [u8; 2usize.pow(EXP)],
            core::array::from_fn::<_, { 2usize.pow(EXP) }, _>(|i| i as u8)
        );
        for _ in 0..10 {
            match controller.connect().await {
                Ok(()) => {
                    log::info!("connected to node");
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
                    let received = str::from_utf8(&buf).todo();
                    log::info!("{received}");

                    break;
                }
                e @ Err(_) => err!(e),
            }
        }
    } else {
        log::warn!("other node not found");
    }
    let mut sniffer = controller.take_sniffer().expect("first sniffer take");
    sniffer.set_promiscuous_mode(true).unwrap();
    sniffer.set_receive_cb(sniffer_callback);

    spawn.must_spawn(beacon_vendor_tx(sniffer, ap_mac));

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

        let mut buffer = [0u8; 1500]; // 1500 is an MTU
        log::info!("read loop");
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    log::info!("EOF");
                    break;
                }
                Ok(_len) => {
                    // let received = str::from_utf8(&buffer[0..len]).unwrap();
                    // log::info!("read {}, {:?}", len, &buffer[0..4]);
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
    // `esp-wifi` recommends at least `92k` for `coex` and `72k` for wifi.
    esp_alloc::heap_allocator!(72_000);

    // Setup and configuration.
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let timer = TimerGroup::new(peripherals.TIMG0);
    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    esp_println::logger::init_logger_from_env();
    esp_hal_embassy::init(timer.timer0);
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
    let ap_mac = wifi_ap_interface.mac_address();
    // let sta_mac = wifi_sta_interface.mac_address();
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
                make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
                make_static!([u8; 2usize.pow(13)], [0; 2usize.pow(13)])
            )
        );
        sta_socket.set_timeout(Some(Duration::from_secs(10)));
        spawn.must_spawn(connection(spawn, controller, sta_socket, ap_mac.into()));
    }
    spawn.must_spawn(boot_button_reply(io.pins.gpio0));

    // Wait for AP stack to finish startup.
    ap_stack
        .wait_link_up()
        .with_timeout(Duration::from_secs(5))
        .await
        .expect("ap up");

    // Give up on sta after a while. Probably failed to connect because of password or the target ssid is missing.
    if let Err(e) = sta_stack
        .wait_link_up()
        .with_timeout(Duration::from_secs(5))
        .await
    {
        log::warn!("STA failed to connect: {e:?}")
    }

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
            make_static!([u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!([u8; 2usize.pow(8)], [0; 2usize.pow(8)])
        )
    );
    sta_socket.set_timeout(Some(Duration::from_secs(10)));

    spawn.must_spawn(reply_with_html(ap_socket));
    spawn.must_spawn(reply_with_html(sta_socket));
}
