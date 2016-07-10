use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use super::icmp;
use super::tcp;
use super::udp;

pub fn process(packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);

            match inner.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => icmp::process(&inner),
                IpNextHeaderProtocols::Tcp => tcp::process(&inner),
                IpNextHeaderProtocols::Udp => udp::process(&inner),
                _ => {}
            }
        }
        _ => {}
    }
}
