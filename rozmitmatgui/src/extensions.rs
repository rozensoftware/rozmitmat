use crate::interfaces::NetworkValidator;

/// Implements NetworkValidator for String
impl NetworkValidator for String
{
    /// check if argument is valid ip address
    fn is_valid_ip(&self) -> bool
    {
        let mut ret = true;
        let ip = self.clone();
        let parts = ip.split(".").collect::<Vec<&str>>();
        
        if parts.len() != 4
        {
            return false;
        }

        for i in parts
        {
            if i.parse::<u8>().is_err()
            {
                ret = false;
                break;
            }
        }

        ret
    }
}
