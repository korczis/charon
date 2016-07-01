#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pcap;

use std::io::Write;
use std::io::stdout;
// use std::thread;
// use std::sync::mpsc;

pub fn list_devices() {
    for device in pcap::Device::list().unwrap() {
        println!("{:?}", device);
    }
}

pub fn process(packet: &pcap::Packet) {
    info!("{:?}", packet);

    print!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
           packet.data[0],
           packet.data[1],
           packet.data[2],
           packet.data[3],
           packet.data[4],
           packet.data[5]);

    print!(" -> ");

    println!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
             packet.data[6],
             packet.data[7],
             packet.data[8],
             packet.data[9],
             packet.data[10],
             packet.data[11]);

    print!("{}.{}.{}.{}",
           packet.data[30],
           packet.data[31],
           packet.data[32],
           packet.data[33]);

    print!(" -> ");

    println!("{}.{}.{}.{}",
             packet.data[34],
             packet.data[35],
             packet.data[36],
             packet.data[37]);

    // println!("{:?}", packet.header);

    // And finally flush output
    stdout().flush().unwrap();
}

pub fn sniff(promisc: bool, snaplen: i32) {
    // let (tx, rx) = mpsc::channel::<pcap::Packet>();
    //
    // thread::spawn(move || {
    //     loop {
    //         let packet = rx.recv().unwrap();
    //         process(packet);
    //     }
    // });

    let main_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(main_device)
        .unwrap()
        .promisc(promisc)
        .snaplen(snaplen)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        process(&packet);
    }
}
