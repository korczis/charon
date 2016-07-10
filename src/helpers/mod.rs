use pcap;

use std::str;

pub fn list_devices() {
    for device in pcap::Device::list().unwrap() {
        println!("{:?}", device);
    }
}

pub fn print_payload(payload: &[u8]) {
    info!("PAYLOAD: {:?}", payload);

    match str::from_utf8(payload) {
        Ok(text) => info!("PAYLOAD (DECODED) {:?}", text),
        _ => {}
    };
}
