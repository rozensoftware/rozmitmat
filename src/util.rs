//#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Write};
use std::process::Command;
use pcap::Device;

/// Opens a pcap device
/// 
/// # Arguments
/// 
/// * `device` - pcap device
/// * `pcap_filter` - pcap filter
/// 
/// # Returns
/// 
/// * `Result<pcap::Capture<pcap::Active>, pcap::Error>` - Result of the operation
pub fn pcap_open(device: Device, pcap_filter: &str) -> Result<pcap::Capture<pcap::Active>, pcap::Error>
{
    let mut cap = device.open()?;
    cap.filter(pcap_filter, true)?;
    Ok(cap)
}

/// Enables or disables ipv4 forwarding
/// 
/// # Arguments
/// 
/// * `enable` - true to enable, false to disable
/// 
/// # Returns
/// 
/// * `Result<(), Error>` - Result of the operation
pub fn ip_forward(enable: bool) -> Result<(), Error> 
{
    const IPV4_FW_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

    let ipv4_fw_path = IPV4_FW_PATH;
    let ipv4_fw_value = match enable {
        true => "1\n",
        false => "0\n",
    };

    let result = match OpenOptions::new().write(true).open(ipv4_fw_path) 
    {
        Ok(mut f) => f.write_all(String::from(ipv4_fw_value).as_bytes()),
        Err(e) => panic!("Unable to open {}: {}", ipv4_fw_path, e),
    };
    
    println!("[+] forwarding ipv4 traffic: {}", enable);
    result
}

/// Gets the mac address of a network interface
/// 
/// # Arguments
/// 
/// * `interface_name` - name of the network interface
/// 
/// # Returns
/// 
/// * `[u8; 6]` - mac address
pub fn get_interface_mac_addr(interface_name: &str) -> [u8; 6] 
{
    let path = format!("/sys/class/net/{}/address", interface_name);
    let mut mac_addr_buf = String::new();
    
    match File::open(&path) 
    {
        Ok(mut f) => f.read_to_string(&mut mac_addr_buf).unwrap(),
        Err(e) => panic!(
            "Unable to read mac address from {} (Network interface down?): {}",
            path, e
        ),
    };

    string_to_mac(mac_addr_buf.trim())
}

/// Converts a mac address to a string
/// 
/// # Arguments
/// 
/// * `mac_addr` - mac address
/// 
/// # Returns
/// 
/// * `String` - mac address as a string
pub fn mac_to_string(mac_addr: &[u8; 6]) -> String 
{
    mac_addr
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

/// Converts a string to a mac address
/// 
/// # Arguments
/// 
/// * `string` - mac address as a string
/// 
/// # Returns
/// 
/// * `[u8; 6]` - mac address
pub fn string_to_mac(string: &str) -> [u8; 6] 
{
    let hx: Vec<u8> = string
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    
    if hx.len() != 6 
    {
        panic!(
            "string_to_mac: mac address octet length is invalid: {}",
            string
        );
    }

    let mut mac_addr = [0u8; 6];
    
    for (&x, p) in hx.iter().zip(mac_addr.iter_mut()) 
    {
        *p = x;
    }
    
    mac_addr
}

///Reads protocol type based on the input packet data
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `u16` - The protocol type
pub(crate) fn read_protocol_type(data: &[u8]) -> u16
{
    let mut array = [0u8; 2];

    for (&x, p) in data[12..14].iter().zip(array.iter_mut()) 
    {
        *p = x;
    }

    u16::from_be_bytes(array)
}

///check if the packet is an ARP packet
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `bool` - True if the packet is an ARP packet
pub fn is_arp_packet(data: &[u8]) -> bool
{
    let protocol_type = read_protocol_type(data);
    protocol_type == 0x0806
}

///Check if the packet is TCP
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `bool` - True if the packet is TCP (IPv4)
pub fn is_tcp_packet(data: &[u8]) -> bool
{
    let protocol_type = read_protocol_type(data);
    protocol_type == 0x0800
}

///Reads MAC address from ARP cache
/// # Arguments
/// * `ip` - The IP address
/// # Returns
/// * `Option<[u8; 6]>` - The MAC address
pub fn read_arp_cache(ip: &str) -> Option<[u8; 6]>
{
    let arp_cache = Command::new("arp")
        .arg("-n")
        .output()
        .expect("failed to execute process");

    let arp_cache = String::from_utf8(arp_cache.stdout).unwrap();
    let arp_cache = arp_cache.split('\n');

    for line in arp_cache 
    {
        let line = line.trim();

        if line.is_empty() 
        {
            continue;
        }

        let line = line.split_whitespace().collect::<Vec<&str>>();

        if line[0] == ip 
        {
            return Some(string_to_mac(line[2]));
        }
    }

    None
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_read_arp_cache()
    {
        let mac = read_arp_cache("192.168.0.1");

        assert!(mac.is_some());
    }
}