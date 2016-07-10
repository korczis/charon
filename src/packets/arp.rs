use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;

use super::super::helpers::print_payload;

pub fn process(packet: &EthernetPacket) {
    match ArpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            print_payload(&inner.payload());
        }
        _ => {}
    }
}
