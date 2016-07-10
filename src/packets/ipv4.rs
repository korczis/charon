use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use super::icmp;
use super::tcp;
use super::udp;

pub fn process_ipv4(packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);

            match inner.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => icmp::process_icmp(&inner),
                IpNextHeaderProtocols::Tcp => tcp::process_tcp(&inner),
                IpNextHeaderProtocols::Udp => udp::process_udp(&inner),
                _ => {}
            }
        }
        _ => {}
    }
}
