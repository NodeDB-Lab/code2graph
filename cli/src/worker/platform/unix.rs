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

/// A cheap, `Send` capability to terminate a contained worker's whole process
/// group without owning its `Child`. Killing is idempotent: signalling a group
/// that has already exited is a harmless no-op (`ESRCH`).
#[derive(Clone, Copy)]
pub struct KillHandle(libc::pid_t);

impl KillHandle {
    /// Requests immediate termination of the worker's process group.
    pub fn kill(&self) {
        // SAFETY: a negative pid addresses the worker's dedicated process group.
        unsafe { libc::kill(-self.0, libc::SIGKILL) };
    }
}

/// Derives a `Send` kill handle for a live containment's process group.
pub fn kill_handle(containment: &Containment) -> KillHandle {
    KillHandle(containment.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn unix_containment_is_available() {
        let mut command = std::process::Command::new("true");
        super::configure_command(&mut command);
    }
}
