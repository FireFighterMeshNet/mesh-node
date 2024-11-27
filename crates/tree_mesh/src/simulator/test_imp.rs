use super::{Event, GetMac, Sniffer};
use critical_section::CriticalSection;
use embassy_net::driver::{Driver, RxToken, TxToken};
use ieee80211::mac_parser::MACAddress;

impl GetMac for MACAddress {
    fn mac(&self) -> MACAddress {
        *self
    }
}
impl Event for MACAddress {
    fn update_handler(f: impl FnMut(CriticalSection<'_>, &Self)) {
        todo!()
    }
}
pub struct TestSniffer;
impl Sniffer for TestSniffer {
    type Error = WifiError;

    fn send_raw_frame(&mut self, data: &[u8]) -> Result<(), WifiError> {
        todo!()
    }
}

#[derive(Debug)]
pub enum WifiError {}
impl core::error::Error for WifiError {}
impl core::fmt::Display for WifiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

pub struct TestController;

pub struct TestRxToken;
impl RxToken for TestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        todo!()
    }
}
pub struct TestTxToken;
impl TxToken for TestTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        todo!()
    }
}
pub struct TestDriver;
impl Driver for TestDriver {
    type RxToken<'a>
        = TestRxToken
    where
        Self: 'a;

    type TxToken<'a>
        = TestTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        cx: &mut core::task::Context,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        todo!()
    }

    fn transmit(&mut self, cx: &mut core::task::Context) -> Option<Self::TxToken<'_>> {
        todo!()
    }

    fn link_state(&mut self, cx: &mut core::task::Context) -> embassy_net::driver::LinkState {
        todo!()
    }

    fn capabilities(&self) -> embassy_net::driver::Capabilities {
        todo!()
    }

    fn hardware_address(&self) -> embassy_net::driver::HardwareAddress {
        todo!()
    }
}

pub struct TestSimulator;
impl super::Simulator for TestSimulator {
    const OUI: [u8; 3] = [0x1, 0, 0];
    type WifiError = WifiError;
    type Controller = TestController;
    type StaDisconnected = MACAddress;
    type StaConnected = MACAddress;
    type ApStadisconnected = MACAddress;
    type ApStaconnected = MACAddress;
    type Sniffer = TestSniffer;

    fn sta_mac_to_ap(mut mac: MACAddress) -> MACAddress {
        mac.0[0] ^= 0xff;
        mac
    }

    fn ap_mac_to_sta(mut mac: MACAddress) -> MACAddress {
        mac.0[0] ^= 0xff;
        mac
    }

    fn set_sniffer_cb(sniffer: &mut Self::Sniffer, f: fn(&[u8])) {
        todo!()
    }

    async fn connect_to_other_node(
        controller: &mut TestController,
        bssid: MACAddress,
        retries: usize,
    ) -> Result<(), Self::WifiError> {
        todo!()
    }
}
