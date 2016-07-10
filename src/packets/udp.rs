use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use super::super::helpers::print_payload;

pub fn process_udp(packet: &Ipv4Packet) {
    match UdpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            print_payload(&inner.payload());
        }
        _ => {}
    }
}
