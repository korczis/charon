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

pub fn process_arp(ethernet: &EthernetPacket) {
    match ArpPacket::new(ethernet.payload()) {
        Some(arp) => info!("{:?}", arp),
        _ => {}
    }
}

pub fn process_ipv4(ethernet: &EthernetPacket) {
    match Ipv4Packet::new(ethernet.payload()) {
        Some(ip) => {
            info!("{:?}", ip);

            match ip.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => process_icmp(&ip),
                IpNextHeaderProtocols::Tcp => process_tcp(&ip),
                IpNextHeaderProtocols::Udp => process_udp(&ip),
                _ => {}
            }
        }
        _ => {}
    }
}

pub fn process_ipv6(ethernet: &EthernetPacket) {
    match Ipv6Packet::new(ethernet.payload()) {
        Some(ip) => {
            info!("{:?}", ip);
        }
        _ => {}
    }
}

pub fn process_icmp(ip: &Ipv4Packet) {
    match IcmpPacket::new(ip.payload()) {
        Some(icmp) => {
            info!("{:?}", icmp);
            process_payload(&icmp.payload());
        }
        _ => {}
    }
}

pub fn process_tcp(ip: &Ipv4Packet) {
    match TcpPacket::new(ip.payload()) {
        Some(tcp) => {
            info!("{:?}", tcp);
            process_payload(&tcp.payload());
        }
        _ => {}
    }
}

pub fn process_udp(ip: &Ipv4Packet) {
    match UdpPacket::new(ip.payload()) {
        Some(udp) => {
            info!("{:?}", udp);
            process_payload(&udp.payload());
        }
        _ => {}
    }
}

pub fn process(packet: &pcap::Packet) {
    info!("{:?}", packet);

    match EthernetPacket::new(packet.data) {
        Some(ethernet) => {
            info!("{:?}", ethernet);

            match ethernet.get_ethertype() {
                EtherTypes::Arp => process_arp(&ethernet),
                EtherTypes::Ipv4 => process_ipv4(&ethernet),
                EtherTypes::Ipv6 => process_ipv6(&ethernet),
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
