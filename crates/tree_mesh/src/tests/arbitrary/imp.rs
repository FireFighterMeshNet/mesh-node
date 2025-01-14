use crate::simulator::{Event, GetMac, Sniffer};
use core::{cell::RefCell, task::Waker};
use critical_section::CriticalSection;
use embassy_net::driver::{Capabilities, Driver, RxToken, TxToken};
use ieee80211::mac_parser::MACAddress;
use std::{
    boxed::Box,
    collections::{BinaryHeap, VecDeque},
    rc::Rc,
};

/// Messages sorted by delivery time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message {
    pub delivery_time: u64,
    pub data: Box<[u8]>,
}

type Shared<T> = Rc<RefCell<T>>;

/// Priority queue of messages to deliver after a delay.
/// Simulates the physical channel.
#[derive(Debug)]
pub struct PhysicalChannel {
    pub in_air: BinaryHeap<Message>,
}
impl PhysicalChannel {
    pub fn new() -> Self {
        Self {
            in_air: BinaryHeap::new(),
        }
    }
    /// Tx new message into the simulated physical medium.
    pub fn tx(&mut self, msg: Message) {
        self.in_air.push(msg);
    }
    /// Poll with the new time of `tick` to deliver messages based on delivery times.
    /// # Note
    /// `tick` should be monotonic
    pub fn poll(&mut self, tick: u64, to_driver: &(SharedTestDriver, SharedTestDriver)) {
        // Get next msg
        let Some(msg) = self.in_air.peek() else {
            return;
        };
        // If delivery time has passed then deliver it
        if tick < msg.delivery_time {
            return;
        }
        let msg = self.in_air.pop().unwrap();

        // Add to both rx interfaces of `to` node.
        let mut drivers = (to_driver.0 .0.borrow_mut(), to_driver.1 .0.borrow_mut());
        drivers.0.rx_queue.borrow_mut().push_back(msg.clone());
        drivers.0.rx_waker.take().map(Waker::wake);
        drivers.1.rx_queue.borrow_mut().push_back(msg.clone());
        drivers.1.rx_waker.take().map(Waker::wake);
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
    cb: Option<fn(&[u8])>,
}
impl Sniffer for TestSniffer {
    type Error = WifiError;

    fn send_raw_frame(&mut self, data: &[u8]) -> Result<(), WifiError> {
        todo!()
    }
}

error_set::error_set!(
    WifiError = {
        Arbitrary(arbitrary::Error),
    };
);

pub struct TestController;

pub struct TestRxToken {
    rx_queue: Shared<VecDeque<Message>>,
}
impl RxToken for TestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut msg = self.rx_queue.borrow_mut().pop_front().unwrap();
        let log_msg = format!("rxed: {:0>2X?}", msg.data);
        let log_msg = log_msg.replace(",", "");
        let stderr = std::io::stderr().lock();
        println!("{log_msg}");
        drop(stderr);
        f(&mut msg.data)
    }
}
pub struct TestTxToken {
    pub tx_queue: Shared<VecDeque<Box<[u8]>>>,
}
impl TxToken for TestTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut data = vec![0; len].into_boxed_slice();
        let res = f(&mut data);
        let log_msg = format!("txed: {data:0>2X?}");
        let log_msg = log_msg.replace(",", "");
        let stderr = std::io::stderr().lock();
        println!("{log_msg}");
        drop(stderr);
        self.tx_queue.borrow_mut().push_back(data);
        res
    }
}
#[derive(Debug, Clone)]
pub struct TestDriver {
    pub mac: [u8; 6],
    pub tx_queue: Shared<VecDeque<Box<[u8]>>>,
    pub rx_queue: Shared<VecDeque<Message>>,
    pub rx_waker: Option<Waker>,
}
impl TestDriver {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            tx_queue: Rc::new(RefCell::new(VecDeque::new())),
            rx_queue: Rc::new(RefCell::new(VecDeque::new())),
            rx_waker: None,
        }
    }
    pub fn tx_tok(&mut self) -> Result<TestTxToken, WifiError> {
        Ok(TestTxToken {
            tx_queue: self.tx_queue.clone(),
        })
    }
    pub fn rx_tok(&mut self) -> Result<Option<(TestRxToken, TestTxToken)>, WifiError> {
        if self.rx_queue.borrow_mut().is_empty() {
            return Ok(None);
        }
        Ok(Some((
            TestRxToken {
                rx_queue: self.rx_queue.clone(),
            },
            TestTxToken {
                tx_queue: self.tx_queue.clone(),
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
                self.rx_waker = Some(cx.waker().clone());
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

/// Shared reference to [`TestDriver`]
#[derive(Debug, Clone)]
pub struct SharedTestDriver(pub Rc<RefCell<TestDriver>>);
impl Driver for SharedTestDriver {
    type RxToken<'a>
        = <TestDriver as Driver>::RxToken<'a>
    where
        Self: 'a;

    type TxToken<'a>
        = <TestDriver as Driver>::TxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        cx: &mut core::task::Context,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.0.borrow_mut().receive(cx)
    }

    fn transmit(&mut self, cx: &mut core::task::Context) -> Option<Self::TxToken<'_>> {
        self.0.borrow_mut().transmit(cx)
    }

    fn link_state(&mut self, cx: &mut core::task::Context) -> embassy_net::driver::LinkState {
        self.0.borrow_mut().link_state(cx)
    }

    fn capabilities(&self) -> Capabilities {
        self.0.borrow_mut().capabilities()
    }

    fn hardware_address(&self) -> embassy_net::driver::HardwareAddress {
        self.0.borrow_mut().hardware_address()
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
