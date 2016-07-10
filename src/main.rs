#[macro_use]
extern crate log;
extern crate env_logger;

extern crate ctrlc;
extern crate charon;
extern crate clap;
extern crate pcap;
extern crate users;

use clap::{Arg, App};

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
// use std::time::Duration;
// use std::thread;

const DESCRIPTION: &'static str = "Kill connections of others"; // env!("CARGO_PKG_DESCRIPTION");
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Received ctrl+c, exiting");
        r.store(false, Ordering::SeqCst);
        exit(0);
    });

    // Specify program options
    let matches = App::new(DESCRIPTION)
        .version(VERSION)
        .author("Tomas Korcak <korczis@gmail.com>")
        .arg(Arg::with_name("interface")
            .help("Interface to listen on")
            .takes_value(true)
            .short("i")
            .long("interface"))
        .arg(Arg::with_name("list")
            .help("List interfaces")
            .short("l")
            .long("list"))
        .arg(Arg::with_name("o")
            .help("Output file to log to")
            .short("o")
            .long("output"))
        .arg(Arg::with_name("promisc")
            .help("Capture packets in promiscuous mode")
            .short("p")
            .long("promisc"))
        .arg(Arg::with_name("snaplen")
            .help("Maximum length of snapped data")
            .takes_value(true)
            .short("s")
            .long("snaplen")
            .default_value("65536"))
        .get_matches();

    env_logger::init().unwrap();

    if matches.is_present("list") {
        charon::helpers::list_devices();
        return;
    }

    let snaplen = matches.value_of("snaplen").map(|value| value.to_string());

    let promisc = matches.is_present("promisc");
    if promisc {
        println!("Capturing packets in promiscuous mode");
    }

    charon::sniff(promisc, snaplen.unwrap().parse::<i32>().unwrap(), None);
}
