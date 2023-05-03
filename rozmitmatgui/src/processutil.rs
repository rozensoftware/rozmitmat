use sysinfo::{PidExt, ProcessExt, Signal, System, SystemExt};

/// Gets the pid of a process with the given name. Uses sysyinfo crate.
/// 
/// # Arguments
/// 
/// * `name` - The name of the process to get the pid of.
/// 
/// # Example
/// 
/// ```
/// use rozmitmat::processutil::get_pid_by_name;
/// 
/// let pid = get_pid_by_name("firefox");
/// ```
/// 
/// # Returns
/// 
/// * `Option<u32>` - The pid of the process if it exists.
pub fn get_pid_by_name(name: &str) -> Option<u32> {
    let mut ret = None;
    let sys = System::new_all();
    for (pid, process) in sys.processes() {
        if process.name() == name {
            let p = *pid;
            ret = Some(p.as_u32());
            break;
        }
    }

    ret
}

/// Sends CTRL-C signal to a process with the given pid. Uses sysyinfo crate.
///
/// # Arguments
///
/// * `pid` - The pid of the process to send the signal to.
///
/// # Example
///
/// ```
/// use rozmitmat::processutil::send_ctrl_c;
///
/// let pid = 1234;
/// send_ctrl_c(pid);
/// ```
pub fn send_ctrl_c(pid: u32) -> bool {
    let sys = System::new_all();
    for (pid_, process) in sys.processes() {
        if (*pid_).as_u32() == pid {
            return process.kill_with(Signal::Interrupt).unwrap();
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pid_by_name() {
        let pid = get_pid_by_name("systemd");
        assert!(pid.is_some());
        println!("pid: {:?}", pid);
    }
}
