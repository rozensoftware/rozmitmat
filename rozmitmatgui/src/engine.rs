use std::io::{BufRead, BufReader};
use std::{process::Stdio, thread};
use std::sync::{Arc, Mutex};

use crate::{networkutils, interfaces::{RunSpoof, NetworkValidator}};

#[derive(Clone)]
pub struct RozmitmatApp
{
    pub output: Arc<Mutex<String>>,
    pub interface_name: String,
    pub target_ip: String,
    pub domain_name: String,
    pub router_ip: String,
    pub redirect_ip: String,
    pub is_dns_spoof_checked: bool,
    pub running: bool,
    pub last_error: String,
}

impl Default for RozmitmatApp
{
    fn default() -> Self 
    {
        let ret = match networkutils::get_router_ip()
        {
            Ok(ip) => ip,
            Err(_) => 
            {
                (String::new(), String::new())
            }
        };

        Self 
        {
            output: Arc::new(Mutex::new(String::new())),
            interface_name: ret.1,
            target_ip: String::new(),
            domain_name: String::new(),   
            router_ip: ret.0,
            redirect_ip: String::new(),
            is_dns_spoof_checked: false,
            running: false,
            last_error: String::new(),
        }
    }
}

impl RunSpoof for RozmitmatApp
{
    fn start(&mut self) 
    {
        let redirect_ip = if self.is_dns_spoof_checked
        {
            self.redirect_ip.clone()
        }
        else
        {
            "none".to_string()
        };

        let domain_name = if self.is_dns_spoof_checked
        {
            self.domain_name.clone()
        }
        else
        {
            "none".to_string()
        };

        self.running = true;

        let roz_data = self.clone();
        let safe_output = Arc::clone(&self.output);

        thread::spawn(move || {
            let file_name = std::env::current_exe().unwrap().parent().unwrap().to_str().unwrap().to_string() + "/rozmitmat";

            // execute command
            let mut command = std::process::Command::new(file_name)
            .arg("-i")
            .arg(&roz_data.interface_name)
            .arg("-t")
            .arg(&roz_data.target_ip)
            .arg("-g")
            .arg(&roz_data.router_ip)
            .arg("-d")
            .arg(&domain_name)
            .arg("-r")
            .arg(&redirect_ip)
            .arg("-v")
            .arg("1")
            .arg("-l")
            .arg("1")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to execute command");

            let stdout = command.stdout.as_mut().unwrap();
            let stdout_reader = BufReader::new(stdout);
            let stdout_lines = stdout_reader.lines();

            for line in stdout_lines
            {
                let mut str = safe_output.lock().unwrap();
                *str += &line.unwrap();
                *str += "\n";
            }

            command.wait().unwrap();
        });
        
        
    }

    fn stop(&mut self) 
    {
    }
}

impl RozmitmatApp
{
    pub fn check_input(&mut self) -> Result<(), String>
    {
        if !self.target_ip.is_valid_ip()
        {
            return Err("Target IP is not valid!".to_string());
        }

        if self.interface_name.is_empty()
        {
            return Err("Interface name cannot be empty!".to_string());
        }

        if self.router_ip.is_empty()
        {
            return Err("Router IP cannot be empty!".to_string());
        }
        else if !self.router_ip.is_valid_ip()
        {
            return Err("Router IP is not valid!".to_string());
        }

        if self.is_dns_spoof_checked
        {
            if self.domain_name.is_empty() || self.domain_name == "none"
            {
                return Err("Domain name cannot be empty!".to_string());
            }
            else if self.redirect_ip.is_empty() || self.redirect_ip == "none"
            {
                return Err("Redirect IP cannot be empty!".to_string());
            }
            else if !self.redirect_ip.is_valid_ip()
            {
                return Err("Redirect IP is not valid!".to_string());
            }
        }

        Ok(())
    }

}