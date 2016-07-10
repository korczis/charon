use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;

pub fn process_ipv6(packet: &EthernetPacket) {
    match Ipv6Packet::new(packet.payload()) {
        Some(inner) => {
            info!("{:?}", inner);
        }
        _ => {}
    }
}
