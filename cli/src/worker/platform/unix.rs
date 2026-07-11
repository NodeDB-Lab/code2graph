// SPDX-License-Identifier: Apache-2.0

//! Unix process-group containment.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

pub struct Containment(libc::pid_t);

pub fn configure_command(command: &mut Command) {
    // SAFETY: the closure performs only async-signal-safe setpgid before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

pub fn contain(child: &mut Child) -> io::Result<Containment> {
    let process_group = libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::other("worker process ID is out of range"))?;
    Ok(Containment(process_group))
}

pub fn terminate(containment: &mut Containment, child: &mut Child) {
    // SAFETY: a negative pid addresses the dedicated process group created above.
    unsafe { libc::kill(-containment.0, libc::SIGKILL) };
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    #[test]
    fn unix_containment_is_available() {
        let mut command = std::process::Command::new("true");
        super::configure_command(&mut command);
    }
}
