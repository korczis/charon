#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pcap;
extern crate pnet;

use std::io::Write;
use std::io::stdout;

use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;

pub fn list_devices() {
    for device in pcap::Device::list().unwrap() {
        println!("{:?}", device);
    }
}

pub fn process_ipv4(ethernet: &EthernetPacket) {
    if let Some(ip) = Ipv4Packet::new(ethernet.payload()) {
        println!("{:?} -> {:?}", ip.get_source(), ip.get_destination());
    }
}

pub fn process_ipv6(ethernet: &EthernetPacket) {
    if let Some(ip) = Ipv6Packet::new(ethernet.payload()) {
        println!("{:?} -> {:?}", ip.get_source(), ip.get_destination());
    }
}

pub fn process(packet: &pcap::Packet) {
    info!("{:?}", packet);

    if let Some(ethernet) = EthernetPacket::new(packet.data) {
        println!("{:?} -> {:?}",
                 ethernet.get_source(),
                 ethernet.get_destination());

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => process_ipv4(&ethernet),
            EtherTypes::Ipv6 => process_ipv6(&ethernet),
            _ => {}
        }
    }

    // And finally flush output
    stdout().flush().unwrap();
}

pub fn sniff(promisc: bool, snaplen: i32) {
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
