//read router ip from /etc/resolv.conf

use std::io::Error as RetErr;
use std::io::ErrorKind;
use std::process::Command;

pub fn get_router_ip() -> Result<(String, String), RetErr> {
    //read output from ip route
    let output = Command::new("ip")
        .arg("route")
        .output()
        .expect("failed to execute command ip route");

    //convert output to string
    let output = String::from_utf8_lossy(&output.stdout);

    //split output into lines
    let lines: Vec<&str> = output.split('\n').collect();

    //get the first line
    let first_line = lines[0];

    //split first line into words
    let words: Vec<&str> = first_line.split(' ').collect();

    if words.len() < 5 {
        return Err(std::io::Error::new(
            ErrorKind::Other,
            "Failed to parse ip route output",
        ));
    }

    //return the second word
    Ok((words[2].to_string(), words[4].to_string()))
}
