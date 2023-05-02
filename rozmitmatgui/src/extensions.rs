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
}
