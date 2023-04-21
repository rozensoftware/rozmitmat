use std::thread;

use nfq::{Queue, Verdict};

fn process_message(msg: &mut nfq::Message) -> Verdict
{
    let mut verdict = Verdict::Accept;

    let mut data = msg.get_payload();

//check if it has DNSRR layer


    verdict
}

pub struct DNSSpoof
{

}

impl DNSSpoof
{
    pub fn new() -> Self
    {
        Self
        {

        }
    }

    pub fn run(&self)
    {
        thread::spawn(move || {
            loop
            {
                let mut queue = match Queue::open() 
                {
                    Ok(q) => q,
                    Err(e) => 
                    {
                        println!("Error opening queue: {}", e);
                        break;
                    }
                };

                match queue.bind(1)
                {
                    Ok(_) => (),
                    Err(e) => 
                    {
                        println!("Error binding: {}", e);
                        break;
                    }
                };
                
                loop 
                {
                    let mut msg = match queue.recv()
                    {
                        Ok(m) => m,
                        Err(e) => 
                        {
                            println!("Error: {}", e);
                            continue;
                        }
                    };

                    let verdict = process_message(&mut msg);

                    msg.set_verdict(verdict);
                    match queue.verdict(msg)
                    {
                        Ok(_) => (),
                        Err(e) => println!("Error: {}", e),
                    }
                }
            }
        });
    }
}

