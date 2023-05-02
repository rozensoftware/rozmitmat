use std::{mem, net::Ipv4Addr};

pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
}

impl IpHeader {
    pub fn new() -> IpHeader {
        IpHeader {
            version: 0,
            ihl: 0,
            tos: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: 0,
            header_checksum: 0,
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    pub fn from_raw(bytes: &[u8]) -> IpHeader {
        let mut ip_header = IpHeader::new();

        ip_header.version = bytes[0] >> 4;
        ip_header.ihl = bytes[0] & 0x0F;
        ip_header.tos = bytes[1];
        ip_header.total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        ip_header.identification = u16::from_be_bytes([bytes[4], bytes[5]]);
        ip_header.flags = bytes[6] >> 5;
        ip_header.fragment_offset = u16::from_be_bytes([bytes[6] & 0x1F, bytes[7]]);
        ip_header.ttl = bytes[8];
        ip_header.protocol = bytes[9];
        ip_header.header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        ip_header.source_ip = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        ip_header.dest_ip = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

        ip_header
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ethernet {
    pub dest_mac: [u8; 6],   /* Target hardware address */
    pub source_mac: [u8; 6], /* Sender hardware address */
    pub ether_type: u16,     /* Ethernet type           */
}

impl Ethernet {
    pub fn new(dest_mac: [u8; 6], source_mac: [u8; 6]) -> Ethernet {
        Ethernet {
            dest_mac,
            source_mac,
            ether_type: u16::to_be(0x0806),
        }
    }

    pub fn from_raw(ethernet_header: &[u8]) -> Option<Ethernet> {
        if ethernet_header.len() < 14 {
            return None;
        }

        let mut array = [0u8; 14];

        for (&x, p) in ethernet_header.iter().zip(array.iter_mut()) {
            *p = x;
        }

        unsafe { Some(mem::transmute::<[u8; 14], Ethernet>(array)) }
    }
}

pub enum ArpType {
    ArpRequest,
    ArpReply,
}

/* ARP Header, (assuming Ethernet+IPv4)                 */
/* Values are stored as big endian                      */
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ArpHeader {
    pub ethernet: Ethernet,  /* Ethernet frame          */
    pub hardware_type: u16,  /* Hardware Type           */
    pub protocol_type: u16,  /* Protocol Type           */
    pub hardware_size: u8,   /* Hardware Address Size   */
    pub protocol_size: u8,   /* Protocol Address Size   */
    pub op_code: u16,        /* Operation Code          */
    pub source_mac: [u8; 6], /* Sender hardware address */
    pub source_ip: [u8; 4],  /* Sender IP address       */
    pub dest_mac: [u8; 6],   /* Target hardware address */
    pub dest_ip: [u8; 4],    /* Target IP address       */
}

impl ArpHeader {
    pub fn new(
        arp_type: ArpType,
        source_mac: [u8; 6],
        source_ip: Ipv4Addr,
        dest_mac: [u8; 6],
        dest_ip: Ipv4Addr,
    ) -> ArpHeader {
        let op_code: u16 = match arp_type {
            ArpType::ArpRequest => 1,
            ArpType::ArpReply => 2,
        };

        ArpHeader {
            ethernet: Ethernet::new(dest_mac, source_mac),
            hardware_type: u16::to_be(0x1),    // Ethernet
            protocol_type: u16::to_be(0x0800), // IPv4
            hardware_size: u8::to_be(6),
            protocol_size: u8::to_be(4),
            op_code: u16::to_be(op_code),
            source_mac,
            source_ip: source_ip.octets(),
            dest_mac,
            dest_ip: dest_ip.octets(),
        }
    }

    pub fn from_raw(arp_header: &[u8]) -> Option<ArpHeader> {
        if arp_header.len() < 42 {
            // ethernet (14) + arp (28)
            return None;
        }

        let mut array = [0u8; 42];

        for (&x, p) in arp_header.iter().zip(array.iter_mut()) {
            *p = x;
        }

        unsafe { Some(mem::transmute::<[u8; 42], ArpHeader>(array)) }
    }

    pub fn to_raw(&self) -> [u8; 42] {
        unsafe { mem::transmute_copy::<ArpHeader, [u8; 42]>(self) }
    }
}
