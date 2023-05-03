extern crate libc;

use clap::{arg, Arg, Command};
use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicBool, atomic::Ordering, Arc},
};

mod dns;
mod dnsspoof;
mod headers;
mod http;
mod rozspoof;
mod util;

#[cfg(target_os = "windows")]
fn main() {
    panic!("This program is not supported on Windows.");
}

fn main() {
    // Get command parameters
    let args = Command::new("rozmitmat")
        .version("rozmitmat 0.1.0")
        .author("Rozen Software <rozsoft@wp.pl>")
        .about("Spoofing ARP packets")
        .arg(
            arg!(--interface <VALUE>)
                .required(true)
                .short('i')
                .help("Interface name"),
        )
        .arg(
            arg!(--target <VALUE>)
                .required(true)
                .short('t')
                .help("Target IP address"),
        )
        .arg(
            arg!(--gateway <VALUE>)
                .required(true)
                .short('g')
                .help("Gateway IP address"),
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .default_value("none")
                .help("Domain address to spoof e.g. example.com"),
        )
        .arg(
            Arg::new("redirectto")
                .short('r')
                .long("redirectto")
                .default_value("none")
                .help("Redirect domain address to IP address"),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .default_value("0")
                .help("Log packets to pcap file"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .default_value("0")
                .help("Verbose mode"),
        )
        .get_matches();

    let interface_name = args.get_one::<String>("interface").unwrap();
    let target_ip = args.get_one::<String>("target").unwrap();
    let gateway_ip = args.get_one::<String>("gateway").unwrap();
    let domain = args.get_one::<String>("domain").unwrap();
    let redirect_to = args.get_one::<String>("redirectto").unwrap();
    let verbose = args.get_one::<String>("verbose").unwrap();
    let log = args.get_one::<String>("log").unwrap();

    //check if we are root
    if unsafe { libc::geteuid() } != 0 {
        println!("[-] You must be root to run this program");
        return;
    }

    if verbose == "0" {
        println!("[*] Verbose mode is disabled");
    }

    //Create arp spoof object
    let arp_spoof = rozspoof::RozSpoof::new(interface_name, verbose == "1", domain, redirect_to);

    //Read own ip
    let my_ip = arp_spoof.get_own_ip();
    println!("[*] My IP: {:?}", my_ip);

    //Read own MAC
    let my_mac = util::get_interface_mac_addr(interface_name);
    println!("[*] My MAC: {}", util::mac_to_string(&my_mac));

    util::ip_forward(true).expect("Unable to enable ip forwarding");

    let mut target_mac = [0u8; 6];
    let mut gateway_mac = [0u8; 6];

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    //Handle CTRL-C signal
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    //Main job
    arp_spoof.run(
        my_mac,
        my_ip,
        target_ip.parse::<Ipv4Addr>().unwrap(),
        gateway_ip.parse::<Ipv4Addr>().unwrap(),
        &mut target_mac,
        &mut gateway_mac,
        log == "1",
        &running,
    );

    //Clean up everything and exit
    util::ip_forward(false).expect("Unable to disable ip forwarding");

    println!("[*] Resetting iptables ... ");

    match util::reset_iptables() {
        Ok(_) => {}
        Err(e) => {
            println!("[!] Unable to reset iptables: {}", e);
        }
    }

    arp_spoof.run_arp_cleanup(
        target_mac,
        target_ip.parse::<Ipv4Addr>().unwrap(),
        gateway_mac,
        gateway_ip.parse::<Ipv4Addr>().unwrap(),
    );
}
