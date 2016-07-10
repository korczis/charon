#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pcap;
extern crate pnet;

use std::io::Write;
use std::io::stdout;

use std::str;

use pnet::packet::ethernet::{EthernetPacket, EtherTypes};

pub mod helpers;
pub mod packets;

pub fn sniff(promisc: bool, snaplen: i32, _output: Option<String>) {
    let main_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(main_device)
        .unwrap()
        .promisc(promisc)
        .snaplen(snaplen)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        process(&packet);
    }
}

pub fn process(packet: &pcap::Packet) {
    info!("{:?}", packet);

    match EthernetPacket::new(packet.data) {
        Some(inner) => {
            info!("{:?}", inner);

            match inner.get_ethertype() {
                EtherTypes::Arp => packets::arp::process(&inner),
                EtherTypes::Ipv4 => packets::ipv4::process(&inner),
                EtherTypes::Ipv6 => packets::ipv6::process(&inner),
                _ => {}
            }
        }
        _ => {}
    }

    // And finally flush output
    stdout().flush().unwrap();
}
