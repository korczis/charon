use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use super::super::helpers::print_payload;

pub fn process(packet: &Ipv4Packet) {
    match IcmpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            print_payload(&inner.payload());
        }
        _ => {}
    }
}
