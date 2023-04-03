use rustdns::Message;

use crate::util;

#[derive(Debug)]
pub struct DnsAnswer
{
    pub name: String,
    pub ip: String,
    pub ttl: u32,
}

#[derive(Debug)]
pub struct DnsQuery
{
    pub name: String,
    pub ip: String,
}

//Check is it a DNS packet
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `bool` - True if the packet is a DNS packet
pub fn is_dns_packet(data: &[u8]) -> bool
{
    let protocol_type = util::read_protocol_type(data);
    protocol_type == 0x0800 && data[23] == 0x11
}

///Extract DNS query from the packet
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `String` - The DNS query
pub fn extract_dns_query(data: &[u8]) -> Option<String>
{
    if !is_dns_packet(data) 
    {
        //println!("extract_dns_query: not a DNS packet");
        return None;
    }

    let dns_header = &data[34..42];
    let dns_flags = u16::from_be_bytes([dns_header[2], dns_header[3]]);

    if dns_flags & 0x8000 != 0 
    {
        //not a DNS query
        return None;
    }

    if dns_flags & 0x000F != 1 
    {
        //not a DNS query with a single question
        return None;
    }

    let mut dns_query = String::new();
    let mut i = 42;

    while data[i] != 0 
    {
        let len = data[i] as usize;
        let mut j = 0;

        while j < len 
        {
            dns_query.push(data[i + j + 1] as char);
            j += 1;
        }

        dns_query.push('.');
        i += len + 1;
    }

    Some(dns_query)
}

pub fn decode_dns(data: &[u8]) -> (Option<Vec<DnsAnswer>>, Option<Vec<DnsQuery>>)
{
    if !is_dns_packet(data) 
    {
        //decode_dns: not a DNS packet
        return (None, None);
    }

    let dns_header = &data[34..42];
    let dns_flags = u16::from_be_bytes([dns_header[2], dns_header[3]]);

    if dns_flags & 0x8000 == 0 
    {
        //decode_dns: not a DNS response
        return (None, None);
    }

    let dns = &data[42..];

    let d = match Message::from_slice(&dns)
    {
        Ok(d) => d,
        Err(_) => return (None, None),
    };

    let answers = d.answers.iter().map(|a| DnsAnswer
    {
        name: a.name.to_string(),
        ip: "".to_string(),
        ttl: a.ttl.subsec_millis(),
    }).collect();

    let queries = d.questions.iter().map(|q| DnsQuery
    {
        name: q.name.to_string(),
        ip: "".to_string(),
    }).collect();

    (Some(answers), Some(queries))
}