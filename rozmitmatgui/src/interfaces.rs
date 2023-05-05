pub trait RunSpoof {
    fn start(&mut self);
    fn stop(&mut self);
}

pub trait NetworkValidator {
    fn is_valid_ip(&self) -> bool;
    fn is_valid_port(&self) -> bool;
}
