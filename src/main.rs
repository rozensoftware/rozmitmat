//install libpcap-dev

extern crate libc;
extern crate env_logger;

use std::{net::Ipv4Addr, sync::{Arc, atomic::AtomicBool, atomic::Ordering}};
use clap::{arg, Command};

mod util;
mod arpspoof;

#[macro_use]
extern crate log;

fn main() 
{
    env_logger::init();

    info!("Starting");
    
    //check if are root
    if unsafe { libc::geteuid() } != 0
    {
        println!("You must be root to run this program");
        return;
    }

    // Get command parameters
    let args = Command::new("rozmitmat")
        .version("rozmitmat 0.1.0")
        .author("Rozen Software <rozsoft@wp.pl>")
        .about("Spoofing ARP packets")
        .arg(arg!(--interface <VALUE>).required(true).short('i').help("Interface name"))
        .arg(arg!(--target <VALUE>).required(true).short('t').help("Target IP address"))
        .arg(arg!(--gateway <VALUE>).required(true).short('g').help("Gateway IP address"))
        .get_matches();

    let interface_name = args.get_one::<String>("interface").unwrap();
    let target_ip = args.get_one::<String>("target").unwrap();
    let gateway_ip = args.get_one::<String>("gateway").unwrap();

    //Create arp spoof object
    let arp_spoof = arpspoof::ARPSpoof::new(interface_name.clone());

    //Read own ip
    let my_ip = arp_spoof.get_own_ip();
    println!("[*] My IP: {:?}", my_ip);

    //Read own MAC
    let my_mac = util::get_interface_mac_addr(&interface_name);    
    println!("[*] My MAC: {:?}", util::mac_to_string(&my_mac));

    util::ip_forward(true).expect("Unable to enable ip forwarding");

    let mut target_mac = [0u8; 6];
    let mut gateway_mac = [0u8; 6];

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    //Handle CTRL-C signal
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    //Main job
    arp_spoof.arp_poisoning(
        my_mac, 
        my_ip, 
        target_ip.parse::<Ipv4Addr>().unwrap().clone(), 
        gateway_ip.parse::<Ipv4Addr>().unwrap().clone(),
        &mut target_mac, &mut gateway_mac,         
        true,
        &running);

    //Clean up everything and exit
    util::ip_forward(false).expect("Unable to disable ip forwarding");

    arp_spoof.run_arp_cleanup( 
        target_mac, 
        target_ip.parse::<Ipv4Addr>().unwrap().clone(), 
        gateway_mac, 
        gateway_ip.parse::<Ipv4Addr>().unwrap().clone());
}
