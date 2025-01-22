use common::UnwrapExt;
use embassy_sync::once_lock::OnceLock;
use esp_wifi::wifi::{event::EventExt, WifiController};
use ieee80211::mac_parser::MACAddress;
use tree_mesh::simulator::{Event, GetMac, Sniffer};

/// Convert from the default sta mac to ap mac.
///
/// See [`esp_hal::efuse::Efuse::mac_address()`], [`esp_wifi::wifi::ap_mac`], [`esp_wifi::wifi::sta_mac`]
// I don't know why the ap and sta macs are chosen the way they are but that makes the below work, so whatever.
pub fn sta_mac_to_ap(mut mac: MACAddress) -> MACAddress {
    mac.0[0] |= 2;
    mac
}
/// Convert from the default ap mac to sta mac.
///
/// See [`esp_hal::efuse::Efuse::mac_address()`], [`esp_wifi::wifi::ap_mac`], [`esp_wifi::wifi::sta_mac`]
// I don't know why the ap and sta macs are chosen the way they are, but that makes the below work, so whatever.
pub fn ap_mac_to_sta(mut mac: MACAddress) -> MACAddress {
    mac.0[0] &= u8::MAX ^ 2;
    mac
}

macro_rules! wrap_event {
    ($wrapper:ident, $event:path, $member:ident) => {
        pub struct $wrapper(pub $event);
        impl Event for $wrapper {
            fn update_handler<F: FnMut(&Self) + Send + Sync + 'static>(mut f: F) {
                <$event>::update_handler(move |event| f(&Self(*event)))
            }
        }
        impl GetMac for $wrapper {
            fn mac(&self) -> MACAddress {
                MACAddress(self.0 .0.$member)
            }
        }
    };
}

wrap_event! { StaDisconnected, esp_wifi::wifi::event::StaDisconnected, bssid }
wrap_event! { StaConnected, esp_wifi::wifi::event::StaConnected, bssid }
wrap_event! { ApStadisconnected, esp_wifi::wifi::event::ApStadisconnected, mac }
wrap_event! { ApStaconnected, esp_wifi::wifi::event::ApStaconnected, mac }

pub struct SnifferWrapper(pub esp_wifi::wifi::Sniffer);
impl Sniffer for SnifferWrapper {
    type Error = esp_wifi::wifi::WifiError;

    fn send_raw_frame(&mut self, data: &[u8]) -> Result<(), esp_wifi::wifi::WifiError> {
        // Send raw frame using wifi-stack's sequence number.
        // Will give an `ESP_ERR_INVALID_ARG` if sending for most configurations if `use_internal_seq_num` != true when wi-fi is initialized.
        // See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/wifi.html#side-effects-to-avoid-in-different-scenarios>
        self.0.send_raw_frame(false, data, true)
    }
}

/// Implementation of [`tree_mesh::simulator::IO`] for esp devices.
pub struct EspIO;
impl tree_mesh::simulator::IO for EspIO {
    /// One of Espressif's OUIs taken from <https://standards-oui.ieee.org/>
    const OUI: [u8; 3] = [0x10, 0x06, 0x1C];
    type WifiError = esp_wifi::wifi::WifiError;
    type Controller = WifiController<'static>;
    type StaDisconnected = StaDisconnected;
    type StaConnected = StaConnected;
    type ApStadisconnected = ApStadisconnected;
    type ApStaconnected = ApStaconnected;
    type Sniffer = SnifferWrapper;

    fn sta_mac_to_ap(mac: MACAddress) -> MACAddress {
        sta_mac_to_ap(mac)
    }

    fn ap_mac_to_sta(mac: MACAddress) -> MACAddress {
        ap_mac_to_sta(mac)
    }

    fn set_sniffer_cb(sniffer: &mut Self::Sniffer, f: fn(&[u8])) {
        static CB: embassy_sync::once_lock::OnceLock<fn(&[u8])> = OnceLock::new();
        CB.init(f).expect("only set sniffer once");
        sniffer
            .0
            .set_receive_cb(|pkt| (CB.try_get().unwrap())(pkt.data))
    }

    /// Try `retries` times to connect.
    /// # Panics
    /// If Wifi is not intialized with STA.
    async fn connect_to_other_node(
        controller: &mut WifiController<'static>,
        bssid: MACAddress,
        retries: usize,
    ) -> Result<(), esp_wifi::wifi::WifiError> {
        let mut config = controller.configuration().unwrap();
        if config.as_client_conf_ref().unwrap().bssid == Some(bssid.0)
            && matches!(controller.is_connected(), Ok(true))
        {
            log::warn!(
                "try connect to {} but already connected",
                MACAddress(config.as_client_conf_ref().unwrap().bssid.unwrap())
            );
            return Ok(());
        }

        config.as_mixed_conf_mut().0.bssid = Some(bssid.0);
        controller.set_configuration(&config).unwrap();

        let _ = embassy_futures::poll_once(controller.disconnect_async())
            .map(|x| x.unwrap_or_log("disconnect unfinished"));

        let mut res = Ok(());
        for _ in 0..retries {
            res = controller.connect_async().await;
            if res.is_ok() {
                break;
            }
        }
        res
    }
}
