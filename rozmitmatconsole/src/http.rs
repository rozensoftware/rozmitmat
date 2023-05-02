use crate::util;

/// Check if the packet is an HTTP packet
///
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `bool` - True if the packet is an HTTP packet
pub fn is_http_packet(data: &[u8]) -> bool {
    let protocol_type = util::read_protocol_type(data);
    protocol_type == 0x0800 && data[23] == 0x06
}

/// Get http body from packet data
/// # Arguments
/// * `data` - The packet data
/// # Returns
/// * `String` - The http body
pub fn get_http_body(data: &[u8]) -> Option<String> {
    if !is_http_packet(data) {
        return None;
    }

    let mut body = String::new();
    let mut i = 0;
    let mut found = false;
    let packet_length = data.len();

    for byte in data {
        if i + 4 >= packet_length {
            break;
        }
        if *byte == 0x0D && data[i + 1] == 0x0A && data[i + 2] == 0x0D && data[i + 3] == 0x0A {
            found = true;
            break;
        }
        i += 1;
    }

    if found {
        for byte in &data[i + 4..] {
            body.push(*byte as char);
        }
    }

    Some(body)
}
