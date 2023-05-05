use crate::interfaces::NetworkValidator;

/// Implements NetworkValidator for String
impl NetworkValidator for String {
    /// check if argument is valid ip address
    fn is_valid_ip(&self) -> bool {
        let mut ret = true;
        let ip = self.clone();
        let parts = ip.split('.').collect::<Vec<&str>>();

        if parts.len() != 4 {
            return false;
        }

        for i in parts {
            if i.parse::<u8>().is_err() {
                ret = false;
                break;
            }
        }

        ret
    }

    /// Check if port is valid
    /// # Arguments
    /// * `port` - The port to check
    /// # Example
    /// ```
    /// use rozmitmat::extensions::is_valid_port;
    /// let port = "8080";
    /// assert!(is_valid_port(port));
    /// ```
    /// # Returns
    /// * `bool` - True if port is valid
    fn is_valid_port(&self) -> bool {
        let mut ret = true;
        let port = self.clone();

        //check if port is a number
        if port.parse::<u16>().is_err() {
            ret = false;
        }

        //check if port is in range 1024-65535
        if let Ok(port) = port.parse::<u32>() {
            if !(1024..=65535).contains(&port) {
                ret = false;
            }
        }

        ret
    }
}

//create unit tests for this module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        let ip = "192.168.0.1".to_string();
        assert!(ip.is_valid_ip());
    }

    #[test]
    fn test_is_invalid_ip_1() {
        let ip = "192.68.".to_string();
        assert!(!ip.is_valid_ip());
    }

    #[test]
    fn test_is_invalid_ip_2() {
        let ip = "192.68.1.s".to_string();
        assert!(!ip.is_valid_ip());
    }

    #[test]
    /// Test if port is valid
    fn test_is_valid_port() {
        let port = "8080".to_string();
        assert!(port.is_valid_port());
    }

    #[test]
    /// Test if port is invalid
    fn test_is_invalid_port_1() {
        let port = "808".to_string();
        assert!(!port.is_valid_port());
    }

    #[test]
    /// Test if port is invalid
    fn test_is_invalid_port_2() {
        let port = "80800".to_string();
        assert!(!port.is_valid_port());
    }
}
