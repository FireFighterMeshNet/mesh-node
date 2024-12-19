use crate::{
    simulator::{Event, GetMac, Sniffer},
    tests::arbitrary_rng::RngUnstructured,
};
use core::task::Waker;
use critical_section::CriticalSection;
use embassy_net::driver::{Capabilities, Driver, RxToken, TxToken};
use ieee80211::mac_parser::MACAddress;
use parking_lot::Mutex;
use rand::Rng;
use std::{
    collections::{BinaryHeap, VecDeque},
    sync::Arc,
};

/// Messages sorted by delivery time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message {
    delivery_time: u64,
    data: Box<[u8]>,
}

type Shared<T> = Arc<Mutex<T>>;

/// Priority queue of messages to deliver and source of entropy.
/// Simulates the physical channel.
#[derive(Debug)]
pub struct PhysicalChannel {
    pub in_air: BinaryHeap<Message>,
    pub rng: RngUnstructured,
    // Message rx_queue for connected nodes.
    pub connected: Vec<Shared<(Option<Waker>, VecDeque<Message>)>>,
}
impl PhysicalChannel {
    /// Tx new message into the simulated physcal medium.
    pub fn tx(&mut self, data: Box<[u8]>) -> Result<(), WifiError> {
        // TODO
        // Randomly (deterministically) drop messages
        // if self.u.arbitrary()? {
        //     return Ok(());
        // }

        // TODO
        // Randomly delay delivery time.
        // let delivery_time = self.u.arbitrary::<u16>()? as u64;
        let delivery_time = 0;

        self.in_air.push(Message {
            delivery_time,
            data,
        });
        Ok(())
    }
    /// Poll with the new time of `tick` to deliver messages based on delivery times.
    /// # Note
    /// `tick` should be monotonic
    pub fn poll(&mut self, tick: u64) {
        // Get next msg
        let Some(msg) = self.in_air.peek() else {
            return;
        };
        // If delivery time has passed then deliver it
        if tick < msg.delivery_time {
            return;
        }
        // Deliver (flood) to all connected.
        for rx in &self.connected {
            // Randomly (deterministically) drop messages to some nodes.
            if self.rng.gen() {
                log::debug!("dropped pkt");
                continue;
            }
            let mut rx = rx.lock();
            rx.1.push_back(msg.clone());
            rx.0.take().map(Waker::wake);
        }
        // Don't need that message anymore.
        self.in_air.pop();
    }
}

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
pub struct TestSniffer {
    phy: Shared<PhysicalChannel>,
    cb: Option<fn(&[u8])>,
}
impl Sniffer for TestSniffer {
    type Error = WifiError;

    fn send_raw_frame(&mut self, data: &[u8]) -> Result<(), WifiError> {
        self.phy.lock().tx(data.into())
    }
}

error_set::error_set!(
    WifiError = {
        Arbitrary(arbitrary::Error),
    };
);

pub struct TestController;

pub struct TestRxToken {
    msgs: Shared<(Option<Waker>, VecDeque<Message>)>,
}
impl RxToken for TestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut msg = self.msgs.lock().1.pop_front().unwrap();
        println!("rxed: {msg:0>2X?}");
        f(&mut msg.data)
    }
}
pub struct TestTxToken {
    phy: Shared<PhysicalChannel>,
}
impl TxToken for TestTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut data = vec![0; len];
        let res = f(&mut data);
        println!("txed: {data:0>2X?}");
        self.phy.lock().tx(data.into()).unwrap();
        res
    }
}
#[derive(Debug, Clone)]
pub struct TestDriver {
    pub mac: [u8; 6],
    pub phy: Shared<PhysicalChannel>,
    // rx waker, messages
    pub local_msgs: Shared<(Option<Waker>, VecDeque<Message>)>,
}
impl TestDriver {
    pub fn new(mac: [u8; 6], phy: Shared<PhysicalChannel>) -> Self {
        Self {
            mac,
            phy,
            local_msgs: Arc::new(Mutex::new((None, VecDeque::new()))),
        }
    }
    pub fn tx_tok(&mut self) -> Result<TestTxToken, WifiError> {
        Ok(TestTxToken {
            phy: self.phy.clone(),
        })
    }
    pub fn rx_tok(&mut self) -> Result<Option<(TestRxToken, TestTxToken)>, WifiError> {
        if self.local_msgs.lock().1.is_empty() {
            return Ok(None);
        }
        Ok(Some((
            TestRxToken {
                msgs: self.local_msgs.clone(),
            },
            TestTxToken {
                phy: self.phy.clone(),
            },
        )))
    }
}
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
        let res = self.rx_tok().unwrap();
        match res {
            Some(x) => Some(x),
            None => {
                self.local_msgs.lock().0 = Some(cx.waker().clone());
                // self.rx_wakers.lock().push(cx.waker().clone());
                None
            }
        }
    }

    fn transmit(&mut self, _cx: &mut core::task::Context) -> Option<Self::TxToken<'_>> {
        Some(self.tx_tok().unwrap())
    }

    fn link_state(&mut self, _cx: &mut core::task::Context) -> embassy_net::driver::LinkState {
        embassy_net::driver::LinkState::Up
    }

    fn capabilities(&self) -> embassy_net::driver::Capabilities {
        let mut caps = Capabilities::default();
        caps.max_transmission_unit = 1500 + 14; // ethernet MTU = 1500 ip MTU + ethernet header
        caps
    }

    fn hardware_address(&self) -> embassy_net::driver::HardwareAddress {
        embassy_net::driver::HardwareAddress::Ethernet(self.mac)
    }
}

pub struct TestIO;
impl crate::IO for TestIO {
    const OUI: [u8; 3] = [0x1, 0, 0];
    type WifiError = WifiError;
    type Controller = TestController;
    type StaDisconnected = MACAddress;
    type StaConnected = MACAddress;
    type ApStadisconnected = MACAddress;
    type ApStaconnected = MACAddress;
    type Sniffer = TestSniffer;

    fn sta_mac_to_ap(mac: MACAddress) -> MACAddress {
        mac
    }

    fn ap_mac_to_sta(mac: MACAddress) -> MACAddress {
        mac
    }

    fn set_sniffer_cb(sniffer: &mut Self::Sniffer, f: fn(&[u8])) {
        sniffer.cb = Some(f);
    }

    async fn connect_to_other_node(
        controller: &mut TestController,
        bssid: MACAddress,
        retries: usize,
    ) -> Result<(), Self::WifiError> {
        todo!()
    }
}
