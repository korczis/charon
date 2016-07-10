use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;

pub fn process_arp(packet: &EthernetPacket) {
    match ArpPacket::new(packet.payload()) {
        Some(inner) => info!("{:?}", inner),
        _ => {}
    }
}
