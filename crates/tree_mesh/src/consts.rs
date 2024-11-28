use embassy_net::{Ipv6Address, Ipv6Cidr};
use ieee80211::mac_parser::MACAddress;

include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

/// SSID shared between all nodes in mesh.
pub const SSID: &'static str = if let Some(x) = option_env!("SSID") {
    x
} else {
    "esp-mesh-default-ssid"
};

/// Protocol version.
pub const PROT_VERSION: u8 = 0;

pub const IP_PREFIX_LEN: u8 = 48;

/// `Ipv6Cidr` from `MACAddress` by embedding the mac as the last 6 bytes of address.
pub const fn sta_cidr_from_mac(mac: MACAddress) -> Ipv6Cidr {
    let mac_ip: [u8; 16] = [
        0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
    ];
    Ipv6Cidr::new(Ipv6Address::from_octets(mac_ip), IP_PREFIX_LEN)
}

/// `MACAddress` from `Ipv6Cidr` by extracting the embedded mac.
pub const fn mac_from_sta_addr(ip: Ipv6Address) -> MACAddress {
    let address = ip.octets();
    MACAddress([
        address[address.len() - 6],
        address[address.len() - 5],
        address[address.len() - 4],
        address[address.len() - 3],
        address[address.len() - 2],
        address[address.len() - 1],
    ])
}

/// Port used for forwarding data.
pub const DATA_PORT: u16 = 8000;

/// Port used for mesh control messages.
pub const CONTROL_PORT: u16 = 8001;

/// CIDR used for gateway (AP).
// The `fc00` prefix used here is dedicated to private networks by the spec.
pub const AP_CIDR: Ipv6Cidr =
    Ipv6Cidr::new(Ipv6Address::new(0xfc00, 0, 0, 0, 0, 0, 0, 1), IP_PREFIX_LEN);
