use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use super::super::helpers::print_payload;

pub fn process_tcp(packet: &Ipv4Packet) {
    match TcpPacket::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
            print_payload(&inner.payload());
        }
        _ => {}
    }
}
