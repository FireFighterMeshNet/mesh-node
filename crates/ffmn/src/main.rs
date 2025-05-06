#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![feature(closure_lifetime_binder)] // for<'a> |&'a| syntax
#![no_std]
#![no_main]

// extern crate alloc;

mod esp32_imp;

use bt_hci::{
    controller::ExternalController,
    param::{AddrKind, BdAddr},
};
use common::*;
use core::{cell::RefCell, sync::atomic::AtomicU8, u8};
use embassy_futures::join::join;
use embassy_net::{
    driver::Driver,
    tcp::TcpSocket,
    udp::{PacketMetadata, UdpSocket},
    IpEndpoint, IpListenEndpoint, Runner, Stack, StackResources, StaticConfigV6,
};
use embassy_time::{Duration, Instant, Timer, WithTimeout};
use embedded_io_async::Write;
use esp32_imp::{EspIO, SnifferWrapper};
use esp_backtrace as _;
use esp_hal::{
    gpio::{GpioPin, Input},
    handler,
    interrupt::InterruptConfigurable,
    peripherals::TIMG0,
    rng::Rng,
    timer::timg::{TimerGroup, Wdt},
};
use esp_wifi::{
    self,
    ble::controller::BleConnector,
    wifi::{
        Configuration, PromiscuousPkt, WifiApDevice, WifiController, WifiDevice, WifiStaDevice,
    },
    EspWifiController,
};
use ieee80211::mac_parser::MACAddress;
use log::warn;
use rand::{rngs::SmallRng, Rng as _, SeedableRng as _};
use tree_mesh::{
    device::{
        ch::{Device, State},
        MeshRunner,
    },
    simulator::IO,
    socket_force_closed, AsyncMutex,
};
use trouble_host::{
    gatt::GattClient,
    prelude::{AdStructure, Central, Characteristic, ConnectParams, ScanConfig},
};

mod consts {
    include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

    // The size of headers in the ethernet payload for the underlying udp to transport the data.
    pub const UDP_FORWARD_HEADER_LEN: usize = {
        let out = smoltcp::wire::ETHERNET_HEADER_LEN
            + smoltcp::wire::IPV6_HEADER_LEN
            + smoltcp::wire::UDP_HEADER_LEN
            + size_of::<tree_mesh::PacketHeader>();
        assert!(out == 70);
        out
    };
    // The size of wrapped headers on tcp messages
    pub const _: () = assert!(
        smoltcp::wire::ETHERNET_HEADER_LEN
            + smoltcp::wire::IPV6_HEADER_LEN
            + smoltcp::wire::TCP_HEADER_LEN
            == 74
    );

    // TODO synchronize this with the esp_config setting.
    // Set the MTU here so the calculated max size including the final headers is <= than the esp32 MTU
    pub const MTU: usize = 1492 // matching ESP32 ESP_WIFI_CONFIG_MTU
    // minus the headers
    - UDP_FORWARD_HEADER_LEN;

    /// Maximum size of udp messages sent on overlayer on mesh.
    #[allow(dead_code)]
    pub const UDP_MESH_MTU: usize = MTU
        - smoltcp::wire::ETHERNET_HEADER_LEN
        - smoltcp::wire::IPV6_HEADER_LEN
        - smoltcp::wire::UDP_HEADER_LEN;

    /// Maximum size of tcp messages sent on overlayer on mesh.
    /* pub const TCP_MESH_MTU: usize = MTU
    - smoltcp::wire::ETHERNET_HEADER_LEN
    - smoltcp::wire::IPV6_HEADER_LEN
    - smoltcp::wire::TCP_HEADER_LEN; */

    pub const PORT: u16 = 6789;

    pub const BLE_SLOTS: usize = 1;
    pub const BLE_CONNECTIONS_MAX: usize = 1;
    pub const BLE_L2CAP_CHANNELS_MAX: usize = 4;
    pub const BLE_L2CAP_MTU: usize = 255;

    // "0000180d-0000-1000-8000-00805f9b34fb"
    // note that's the 128 bit version of the 16 bit `180d` characteristic
    // See <https://stackoverflow.com/questions/36212020/how-can-i-convert-a-bluetooth-16-bit-service-uuid-into-a-128-bit-uuid>
    // pub const BLE_SERIVCE_UUID_128: trouble_host::attribute::Uuid =
    //     trouble_host::attribute::Uuid::Uuid128([
    //         00, 00, 0x18, 0x0d, 00, 00, 0x10, 00, 0x80, 00, 00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
    //     ]);
    pub const BLE_SERIVCE_UUID_16: [u8; 2] = [0x0d, 0x18]; // reversed because ? maybe little endian
    pub const BLE_SERIVCE_UUID_16_WRAPPED: trouble_host::attribute::Uuid =
        trouble_host::attribute::Uuid::new_short(0x180d);
    // pub const BLE_CHARACTERISTIC_UUID: trouble_host::attribute::Uuid =
    //     trouble_host::attribute::Uuid::new_short(0x2a37);
    pub const BLE_CHARACTERISTIC_UUID_LONG: fn() -> trouble_host::attribute::Uuid = || {
        let mut arr = [
            0x00, 0x00, 0x2A, 0x37, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b,
            0x34, 0xfb,
        ];
        arr.reverse(); // switch to little endian.
        trouble_host::attribute::Uuid::new_long(arr)
    };
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

/// Run the mesh overlay network stack.
#[embassy_executor::task]
async fn mesh_task(
    mut stack_runner: Runner<'static, Device<'static, { consts::MTU }>>,
    device_runner: MeshRunner<'static, { consts::MTU }>,
) -> ! {
    join(device_runner.run(), stack_runner.run()).await.0
}

struct CustomBLEEventHandler {
    candidate_peripheral: RefCell<Option<(AddrKind, BdAddr)>>,
}
impl CustomBLEEventHandler {
    const fn new() -> Self {
        Self {
            candidate_peripheral: RefCell::new(None),
        }
    }
}
impl trouble_host::prelude::EventHandler for CustomBLEEventHandler {
    fn on_adv_reports(&self, reports: bt_hci::param::LeAdvReportsIter) {
        log::trace!("scan has {:?} elements", reports.len());
        if self.candidate_peripheral.borrow().is_none() {
            for report in reports.filter_map(Result::ok) {
                log::trace!("addr: {:x?}", report.addr);

                for ad in AdStructure::decode(report.data) {
                    let Ok(ad) = ad else { break };
                    log::trace!("ad structure: {:?}", ad);
                    let AdStructure::ServiceUuids16(uuids) = ad else {
                        continue;
                    };
                    if uuids.is_empty() {
                        continue;
                    }
                    if uuids[0] == consts::BLE_SERIVCE_UUID_16 {
                        log::info!("found match uuid");
                        self.candidate_peripheral
                            .borrow_mut()
                            .replace((report.addr_kind, report.addr));
                    }
                }
                log::trace!("advertisement: {report:?}");
            }
        }
    }
}

/// Run the ble stack
#[embassy_executor::task]
async fn ble_task(
    event_handler: &'static CustomBLEEventHandler,
    mut ble_runner: trouble_host::prelude::Runner<
        'static,
        ExternalController<esp_wifi::ble::controller::BleConnector<'static>, { consts::BLE_SLOTS }>,
    >,
) {
    ble_runner.run_with_handler(event_handler).await.unwrap();
}

#[embassy_executor::task]
async fn ble_connection(
    event_handler: &'static CustomBLEEventHandler,
    mut central: Central<'static, ExternalController<BleConnector<'static>, { consts::BLE_SLOTS }>>,
    stack: &'static trouble_host::Stack<
        'static,
        ExternalController<BleConnector<'static>, { consts::BLE_SLOTS }>,
    >,
) {
    let config = || trouble_host::prelude::ConnectConfig {
        scan_config: ScanConfig {
            filter_accept_list: &[],
            // interval: Duration::from_millis(1349),
            // window: Duration::from_millis(499),
            active: true,
            ..Default::default()
        },
        connect_params: ConnectParams::default(),
    };
    log::info!("scanning");
    loop {
        let mut scanner = trouble_host::scan::Scanner::new(central);
        match scanner.scan(&config().scan_config).await {
            Ok(session) => drop(session),
            e @ Err(_) => {
                err!(e);
                break;
            }
        };
        // Hack: See <https://github.com/embassy-rs/trouble/pull/313>
        // If you remove either `yield_now` connecting gives a `BleHost(Hci(Command Disallowed)` error.
        embassy_futures::yield_now().await;
        embassy_futures::yield_now().await;
        central = scanner.into_inner();
        let Some(new_address) = event_handler.candidate_peripheral.borrow_mut().take() else {
            log::trace!("no new on scan");
            continue;
        };

        let filter_list = [(new_address.0, &new_address.1)];
        log::info!("connecting: {:?}", new_address);
        let connection = match central
            .connect(&{
                let mut out = config();
                out.scan_config.filter_accept_list = &filter_list;
                out
            })
            .inspect("connect")
            .await {
                Ok(x) => x,
                e @ Err(_) => {err!(e, "connect"); continue}
            }
            // .todo_msg("connect")
            ;
        log::info!(
            "connection: {:x?} {:?} {:?} {:?}",
            connection.peer_address(),
            connection.role(),
            connection.handle(),
            connection.is_connected()
        );
        let client = GattClient::<_, 10, { consts::BLE_L2CAP_MTU }>::new(stack, &connection)
            .await
            .todo_msg("new gatt");
        log::trace!("services by uuid");
        let ((), ()) = join(async { client.task().await.todo() }, async {
            let services = client
                .services_by_uuid(&consts::BLE_SERIVCE_UUID_16_WRAPPED)
                .inspect("services by uuid")
                .with_timeout(Duration::from_millis(5000))
                .await
                .todo_msg("services timeout")
                .todo_msg("services err");
            log::info!("services {:?}", services);

            assert_eq!(services.len(), 1, "todo: != 1");
            let service = services.first().unwrap();
            let characteristic: Characteristic<heapless::Vec<u8, 8>> = client
                .characteristic_by_uuid(service, &consts::BLE_CHARACTERISTIC_UUID_LONG())
                .await
                .todo_msg("characteristic");
            let mut listener = client
                .subscribe(&characteristic, false)
                .await
                .todo_msg("subscribe");
            let ((), ()) = join(
                async {
                    loop {
                        let notification = listener.next().await;
                        log::info!("notification: {:?}", notification.as_ref());
                    }
                },
                async {
                    /* loop {
                        let mut buf = heapless::Vec::<u8, 8>::new();
                        let len = client
                            .read_characteristic(&characteristic, &mut buf)
                            .await
                            .todo_msg("read characteristic");
                        log::info!("read val: {:?}", &buf[..len]);
                    } */
                },
            )
            .await;
        })
        .await;
    }
}

#[embassy_executor::task]
async fn tree_mesh_task(
    sniffer: <EspIO as IO>::Sniffer,
    controller: &'static AsyncMutex<<EspIO as IO>::Controller>,
    ap_stack: Stack<'static>,
    sta_stack: Stack<'static>,
    ap_mac: MACAddress,
) -> ! {
    let ap_rx_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            ap_stack,
            make_static!(const [u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!(const [u8; 2usize.pow(8)], [0; 2usize.pow(8)])
        )
    );
    ap_rx_socket.set_timeout(Some(Duration::from_secs(10)));

    let sta_tx_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            sta_stack,
            make_static!(const [u8; 2usize.pow(10)], [0; 2usize.pow(10)]),
            make_static!(const [u8; 2usize.pow(8)], [0; 2usize.pow(8)])
        )
    );
    sta_tx_socket.set_timeout(Some(Duration::from_secs(10)));

    tree_mesh::run::<EspIO>(sniffer, controller, ap_rx_socket, sta_tx_socket, ap_mac).await
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
    tree_mesh::sniffer_callback::<esp32_imp::EspIO>(&pkt.data);

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

/// Setup both AP and STA.
async fn wifi_connection(
    spawn: embassy_executor::Spawner,
    mut controller: WifiController<'static>,
    ap_stack: Stack<'static>,
    sta_stack: Stack<'static>,
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

    sniffer.set_receive_cb(sniffer_callback);

    spawn.must_spawn(tree_mesh_task(
        SnifferWrapper(sniffer),
        controller,
        ap_stack,
        sta_stack,
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

/// Initialize a global heap allocator providing a heap of the given size in
/// bytes. This supports attributes.
/// ```
/// // Use 64kB in the same region stack uses (dram_seg), for the heap.
/// heap_allocator(size: 64000)
/// // Use 64kB in dram2_seg for the heap, which is otherwise unused.
/// heap_allocator(#[link_section = ".dram2_uninit"] size: 64000)
/// ```
#[macro_export]
macro_rules! heap_allocator {
    ($size:expr) => (heap_allocator!(size: $size));
    ($(#[$m:meta])* size: $size:expr) => {{
        $(#[$m])*
        static mut HEAP: core::mem::MaybeUninit<[u8; $size]> = core::mem::MaybeUninit::uninit();

        #[allow(static_mut_refs)]
        unsafe {
            esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
                HEAP.as_mut_ptr() as *mut u8,
                $size,
                esp_alloc::MemoryCapability::Internal.into(),
            ));
        }
    }};
}

#[esp_hal_embassy::main]
async fn main(spawn: embassy_executor::Spawner) {
    // Provides #[global_allocator] with given number of bytes.
    // Bigger value here means smaller space left for stack if linked in dram_seg, as is done by default.
    // `esp-wifi` recommends at least `92k` for `coex` and `72k` for wifi.
    heap_allocator!(
        // Use dram2_seg and the bootloader memory.
        // See the linker and memory layout files <https://github.com/esp-rs/esp-hal/tree/main/esp-hal/ld/esp32> and the pr <https://github.com/esp-rs/esp-hal/pull/2079>
        #[unsafe(link_section = ".dram2_uninit")]
        size: 98767 // max size of dram2_seg esp32
    );

    // Setup and configuration.
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
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
    // Log config.
    log::info!("TREE_LEVEL: {:?}", consts::TREE_LEVEL);
    log::info!("DENYLIST_MACS:");
    for mac in consts::DENYLIST_MACS.into_iter().map(|x| MACAddress(*x)) {
        log::info!("{mac:?}")
    }

    // Setup wifi/ble and log config.
    let init = make_static!(
        EspWifiController<'static>,
        esp_wifi::init(timer.timer1, rng, peripherals.RADIO_CLK).unwrap()
    );
    let (wifi_ap_device, wifi_sta_device, wifi_controller) =
        esp_wifi::wifi::new_ap_sta(&*init, peripherals.WIFI).unwrap();
    let ble_connector = esp_wifi::ble::controller::BleConnector::new(&*init, peripherals.BT);
    let ble_resources = make_static!(const
        trouble_host::HostResources::<
            { consts::BLE_CONNECTIONS_MAX },
            { consts::BLE_L2CAP_CHANNELS_MAX },
            { consts::BLE_L2CAP_MTU },
        >,
        trouble_host::HostResources::new()
    );
    let ble_stack = make_static!(
        trouble_host::Stack<
            'static,
            ExternalController<BleConnector<'static>, { consts::BLE_SLOTS }>,
        >,
        trouble_host::new(ExternalController::new(ble_connector), ble_resources,)
            .set_random_address(trouble_host::Address {
                kind: AddrKind::RANDOM,
                addr: BdAddr::new(prng.r#gen()),
            })
    );
    let ap_mac = MACAddress(wifi_ap_device.mac_address());
    let sta_mac = MACAddress(wifi_sta_device.mac_address());
    log::info!("ap_mac: {}; sta_mac: {}", ap_mac, sta_mac);
    assert_eq!(EspIO::ap_mac_to_sta(ap_mac), sta_mac);
    assert_eq!(EspIO::sta_mac_to_ap(sta_mac), ap_mac);

    assert!(consts::MTU <= wifi_ap_device.capabilities().max_transmission_unit);
    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_device,
        embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: tree_mesh::consts::AP_CIDR,
            gateway: Some(tree_mesh::consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(const
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>,
            StackResources::new()
        ),
        prng.r#gen(),
    );
    assert!(consts::MTU <= wifi_sta_device.capabilities().max_transmission_unit);
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_device,
        embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: tree_mesh::consts::sta_cidr_from_mac(ap_mac),
            gateway: Some(tree_mesh::consts::AP_CIDR.address()),
            dns_servers: Default::default(),
        }),
        make_static!(const
            StackResources::<{ tree_mesh::consts::MAX_NODES * 2 }>,
            StackResources::new()
        ),
        prng.r#gen(),
    );

    spawn.must_spawn(ap_task(ap_runner));
    spawn.must_spawn(sta_task(sta_runner));
    spawn.must_spawn(boot_button_reply(peripherals.GPIO0));
    wifi_connection(spawn, wifi_controller, ap_stack, sta_stack, ap_mac).await;

    // Setup mesh overlay device.
    let ap_socket = UdpSocket::new(
        ap_stack,
        make_static!(const
            [PacketMetadata; tree_mesh::consts::MAX_NODES],
            [PacketMetadata::EMPTY; tree_mesh::consts::MAX_NODES]
        ),
        make_static!(const [u8; consts::MTU * 3], [0; consts::MTU * 3]),
        make_static!(const
            [PacketMetadata; tree_mesh::consts::MAX_NODES],
            [PacketMetadata::EMPTY; tree_mesh::consts::MAX_NODES]
        ),
        make_static!(const [u8; consts::MTU * 3], [0; consts::MTU * 3]),
    );
    let sta_socket = UdpSocket::new(
        sta_stack,
        make_static!(const
            [PacketMetadata; tree_mesh::consts::MAX_NODES],
            [PacketMetadata::EMPTY; tree_mesh::consts::MAX_NODES]
        ),
        make_static!(const [u8; consts::MTU * 3], [0; consts::MTU * 3]),
        make_static!(const
            [PacketMetadata; tree_mesh::consts::MAX_NODES],
            [PacketMetadata::EMPTY; tree_mesh::consts::MAX_NODES]
        ),
        make_static!(const [u8; consts::MTU * 3], [0; consts::MTU * 3]),
    );
    let (mesh_device, mesh_device_runner) = tree_mesh::device::new(
        make_static!(const
            State::<
                { consts::MTU },
                { tree_mesh::consts::MAX_NODES },
                { tree_mesh::consts::MAX_NODES },
            >,
            State::new()
        ),
        embassy_net::driver::HardwareAddress::Ethernet(ap_mac.0),
        ap_mac,
        ap_socket,
        sta_socket,
    );
    let (mesh_stack, mesh_stack_runner) = embassy_net::new(
        mesh_device,
        embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: tree_mesh::consts::sta_cidr_from_mac(ap_mac),
            gateway: None,
            dns_servers: Default::default(),
        }),
        make_static!(const StackResources::<1>, StackResources::new()),
        prng.r#gen(),
    );
    spawn.must_spawn(mesh_task(mesh_stack_runner, mesh_device_runner));

    let trouble_host::Host {
        central,
        runner,
        peripheral: _,
        ..
    } = ble_stack.build();
    let event_handler = &*make_static!(const CustomBLEEventHandler, CustomBLEEventHandler::new());
    spawn.must_spawn(ble_task(event_handler, runner));
    spawn.must_spawn(ble_connection(event_handler, central, ble_stack));

    // Wait for AP stack to finish startup.
    ap_stack
        .wait_link_up()
        .with_timeout(Duration::from_secs(5))
        .await
        .expect("ap up");

    let mesh_tcp_socket = make_static!(
        TcpSocket<'static>,
        TcpSocket::new(
            mesh_stack,
            make_static!(const [u8; 2usize.pow(12)], [0; 2usize.pow(12)]),
            make_static!(const [u8; 2usize.pow(12)], [0; 2usize.pow(12)])
        )
    );
    mesh_tcp_socket.set_timeout(Some(Duration::from_secs(10)));

    let send_to = todo!(
        "enter ap_mac of node to send to. e.g. `MACAddress([0xaa, 0xbb, 0xcc, 0xcc, 0xdd, 0xee])`"
    );
    if consts::TREE_LEVEL != Some(0) && ap_mac != send_to {
        loop {
            // Wait to connect.
            while let Err(e) = mesh_tcp_socket
                .connect(IpEndpoint {
                    addr: tree_mesh::consts::sta_cidr_from_mac(send_to)
                        .address()
                        .into(),
                    port: consts::PORT,
                })
                .await
            {
                err!(Err::<(), _>(e))
            }
            // benchmark sending forwarded pkts
            err!(mesh_tcp_socket.write_all(b"hello world 123").await);
            let start = Instant::now();
            for i in 0..100 {
                err!(esp_println::dbg!(
                    mesh_tcp_socket.write_all(&[i; 2024]).await
                ));
            }
            err!(mesh_tcp_socket.flush().await);
            let end = Instant::now();
            log::error!(
                "\n{}ms elapsed transferring {}x{} bytes\n",
                (end - start).as_millis(),
                100,
                2024
            );
            socket_force_closed(mesh_tcp_socket).await;
            embassy_futures::yield_now().await;
        }
    } else {
        loop {
            for _ in 0..10 {
                let mut buf = [0; consts::MTU];
                err!(
                    mesh_tcp_socket
                        .accept(IpListenEndpoint {
                            addr: None,
                            port: consts::PORT,
                        })
                        .await
                );
                while let Ok(len) = esp_println::dbg!(mesh_tcp_socket.read(&mut buf).await) {
                    if len == 0 {
                        // eof
                        break;
                    }
                    warn!("rxed {:?}", &buf[..len.min(10)]);
                }
                socket_force_closed(mesh_tcp_socket).await;
            }
        }
    }
}
