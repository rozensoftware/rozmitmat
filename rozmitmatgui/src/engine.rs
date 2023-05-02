use std::io::{prelude::*, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::processutil::{get_pid_by_name, send_ctrl_c};
use crate::{
    interfaces::{NetworkValidator, RunSpoof},
    networkutils,
};

const ROZMITMAT_CONSOLE_NAME: &str = "rozmitmat";

#[derive(Clone)]
pub struct RozmitmatApp {
    pub output: Arc<Mutex<String>>,
    pub interface_name: String,
    pub target_ip: String,
    pub domain_name: String,
    pub router_ip: String,
    pub redirect_ip: String,
    pub is_dns_spoof_checked: bool,
    pub running: Arc<Mutex<bool>>,
    pub last_error: String,
    pub verbose: bool,
}

impl Default for RozmitmatApp {
    fn default() -> Self {
        let ret = match networkutils::get_router_ip() {
            Ok(ip) => ip,
            Err(_) => (String::new(), String::new()),
        };

        Self {
            output: Arc::new(Mutex::new(String::new())),
            interface_name: ret.1,
            target_ip: String::new(),
            domain_name: String::new(),
            router_ip: ret.0,
            redirect_ip: String::new(),
            is_dns_spoof_checked: false,
            running: Arc::new(Mutex::new(false)),
            last_error: String::new(),
            verbose: false,
        }
    }
}

impl RunSpoof for RozmitmatApp {
    fn start(&mut self) {
        let redirect_ip = if self.is_dns_spoof_checked {
            self.redirect_ip.clone()
        } else {
            "none".to_string()
        };

        let domain_name = if self.is_dns_spoof_checked {
            self.domain_name.clone()
        } else {
            "none".to_string()
        };

        let file_name = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
            + "/rozmitmat";
        let safe_output = Arc::clone(&self.output);
        let safe_running = Arc::clone(&self.running);
        let verbose = if self.verbose { "1" } else { "0" };

        let roz_data = self.clone();

        thread::spawn(move || {
            // execute command
            let mut command = Command::new(file_name)
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
                .arg(verbose)
                .arg("-l")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to execute rozmitmat command");

            let mut r = safe_running.lock().unwrap();
            *r = true;
            drop(r);

            {
                let stdout = command.stdout.take().unwrap();
                let stderr = command.stderr.take().unwrap();

                let mut reader_out = BufReader::new(stdout);
                let err_lines = BufReader::new(stderr).lines();

                loop {
                    let stdout_bytes = match reader_out.fill_buf() {
                        Ok(stdout_bytes) => {
                            let mut output = safe_output.lock().unwrap();
                            if let Ok(b) = std::str::from_utf8(stdout_bytes) {
                                output.push_str(b);
                            }

                            stdout_bytes.len()
                        }

                        _ => break,
                    };

                    if stdout_bytes == 0 {
                        break;
                    }

                    reader_out.consume(stdout_bytes);
                }

                for line in err_lines {
                    let mut str = safe_output.lock().unwrap();
                    *str += &line.unwrap();
                    *str += "\n";
                }
            }

            command.wait().unwrap();
            let mut r = safe_running.lock().unwrap();
            *r = false;
        });
    }

    fn stop(&mut self) {
        let mut r = self.running.lock().unwrap();

        if *r {
            *r = false;

            if let Some(pid) = get_pid_by_name(ROZMITMAT_CONSOLE_NAME) {
                let ret = send_ctrl_c(pid);
                if !ret {
                    let _ = Command::new("killall").arg(ROZMITMAT_CONSOLE_NAME).output();
                }
            };
        }
    }
}

impl RozmitmatApp {
    pub fn check_input(&mut self) -> Result<(), String> {
        if !self.target_ip.is_valid_ip() {
            return Err("Target IP is not valid!".to_string());
        }

        if self.interface_name.is_empty() {
            return Err("Interface name cannot be empty!".to_string());
        }

        if self.router_ip.is_empty() {
            return Err("Router IP cannot be empty!".to_string());
        } else if !self.router_ip.is_valid_ip() {
            return Err("Router IP is not valid!".to_string());
        }

        if self.is_dns_spoof_checked {
            if self.domain_name.is_empty() || self.domain_name == "none" {
                return Err("Domain name cannot be empty!".to_string());
            } else if self.redirect_ip.is_empty() || self.redirect_ip == "none" {
                return Err("Redirect IP cannot be empty!".to_string());
            } else if !self.redirect_ip.is_valid_ip() {
                return Err("Redirect IP is not valid!".to_string());
            }
        }

        Ok(())
    }
}
