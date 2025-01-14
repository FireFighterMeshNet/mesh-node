//! Abstract out io so it can be simulated in tests.

use ieee80211::mac_parser::MACAddress;

pub trait GetMac {
    fn mac(&self) -> MACAddress;
}
pub trait Event {
    fn update_handler<F: FnMut(&Self) + Sync + Send + 'static>(f: F);
}
pub trait Sniffer {
    type Error: core::fmt::Debug;

    /// Send raw ieee80211 frame.
    fn send_raw_frame(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

pub trait IO {
    const OUI: [u8; 3];
    type WifiError: core::fmt::Debug;
    type Controller;
    type StaDisconnected: Event + GetMac;
    type StaConnected: Event + GetMac;
    type ApStadisconnected: Event + GetMac;
    type ApStaconnected: Event + GetMac;
    type Sniffer: Sniffer<Error = Self::WifiError>;

    fn sta_mac_to_ap(mac: MACAddress) -> MACAddress;
    fn ap_mac_to_sta(mac: MACAddress) -> MACAddress;

    /// Register sniffer callback.
    /// # Panics
    /// May panic if called multiple times.
    fn set_sniffer_cb(sniffer: &mut Self::Sniffer, cb: fn(&[u8]));

    #[allow(async_fn_in_trait)]
    async fn connect_to_other_node(
        controller: &mut Self::Controller,
        bssid: MACAddress,
        retries: usize,
    ) -> Result<(), Self::WifiError>;
}
