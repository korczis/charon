#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pcap;
extern crate pnet;

use std::io::Write;
use std::io::stdout;

// use std::sync::mpsc::{Sender, Receiver};
// use std::sync::mpsc;
// use std::thread;

use std::str;

use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

pub fn list_devices() {
    for device in pcap::Device::list().unwrap() {
        println!("{:?}", device);
    }
}

pub fn process_payload(payload: &[u8]) {
    info!("PAYLOAD: {:?}", payload);

    match str::from_utf8(payload) {
        Ok(text) => info!("PAYLOAD (DECODED) {:?}", text),
        _ => {}
    };
}

pub fn process_arp(packet: &EthernetPacket) {
    match ArpPacket::new(packet.payload()) {
        Some(inner) => info!("{:?}", inner),
        _ => {}
    }
}

pub fn process_ipv4(packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);

            match inner.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => process_icmp(&inner),
                IpNextHeaderProtocols::Tcp => process_tcp(&inner),
                IpNextHeaderProtocols::Udp => process_udp(&inner),
                _ => {}
            }
        }
        _ => {}
    }
}

pub fn process_ipv6(packet: &EthernetPacket) {
    match Ipv6Packet::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
        }
        _ => {}
    }
}

pub fn process_icmp(packet: &Ipv4Packet) {
    match IcmpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            process_payload(&inner.payload());
        }
        _ => {}
    }
}

pub fn process_tcp(packet: &Ipv4Packet) {
    match TcpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            process_payload(&inner.payload());
        }
        _ => {}
    }
}

pub fn process_udp(packet: &Ipv4Packet) {
    match UdpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            process_payload(&inner.payload());
        }
        _ => {}
    }
}

pub fn process(packet: &pcap::Packet) {
    info!("{:?}", packet);

    match EthernetPacket::new(packet.data) {
        Some(inner) => {
            info!("{:?}", inner);

            match inner.get_ethertype() {
                EtherTypes::Arp => process_arp(&inner),
                EtherTypes::Ipv4 => process_ipv4(&inner),
                EtherTypes::Ipv6 => process_ipv6(&inner),
                _ => {}
            }
        }
        _ => {}
    }

    // And finally flush output
    stdout().flush().unwrap();
}

pub fn sniff(promisc: bool, snaplen: i32, _output: Option<String>) {
    let main_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(main_device)
        .unwrap()
        .promisc(promisc)
        .snaplen(snaplen)
        .open()
        .unwrap();

    // let (tx, rx): (Sender<i32>, Receiver<i32>) = mpsc::channel();
    //
    // thread::spawn(move || {
    //     loop {
    //         let data = rx.recv();
    //         println!("{:?}", data);
    //     }
    // });

    while let Ok(packet) = cap.next() {
        process(&packet);
    }
}
