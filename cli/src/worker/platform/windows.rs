// SPDX-License-Identifier: Apache-2.0

//! Windows Job Object containment.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

pub struct Containment(HANDLE);

impl Drop for Containment {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this owns the non-null Job Object handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn configure_command(_: &mut Command) {}

fn kill_on_close_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    // SAFETY: the Windows API accepts a zero-initialized limits structure.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits
}

/// Assigns a child to a kill-on-close Job Object immediately after spawn.
pub fn contain(child: &mut Child) -> io::Result<Containment> {
    // SAFETY: null attributes/name create an unnamed Job Object.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let containment = Containment(job);
    let limits = kill_on_close_limits();
    // SAFETY: limits is correctly sized for this information class.
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let process: HANDLE = child.as_raw_handle();
    // SAFETY: the child handle remains valid while Child is alive.
    if unsafe { AssignProcessToJobObject(job, process) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(containment)
}

pub fn terminate(containment: &mut Containment, child: &mut Child) {
    if !containment.0.is_null() {
        // Closing a kill-on-close job terminates every process still assigned to it.
        // SAFETY: this owns the non-null Job Object handle and clears it immediately.
        unsafe { CloseHandle(containment.0) };
        containment.0 = std::ptr::null_mut();
    }
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn kill_on_close_job_limits_use_the_windows_layout() {
        let limits = kill_on_close_limits();
        assert_eq!(
            limits.BasicLimitInformation.LimitFlags,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        );
        assert_eq!(
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
            std::mem::size_of_val(&limits)
        );
    }

    #[test]
    fn job_object_child_process() {
        if let Some(ready) = std::env::var_os("CODE2GRAPH_JOB_OBJECT_READY") {
            fs::write(ready, b"ready").expect("signal ready");
            thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn closing_job_object_terminates_an_assigned_process() {
        let directory = tempdir().expect("temporary directory");
        let ready = directory.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["job_object_child_process", "--nocapture"])
            .env("CODE2GRAPH_JOB_OBJECT_READY", &ready)
            .spawn()
            .expect("long-running child");
        let containment = match contain(&mut child) {
            Ok(containment) => containment,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Job Object containment failed: {error}");
            }
        };

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() {
            if child.try_wait().expect("poll child").is_some() {
                panic!("Job Object child exited before reporting ready");
            }
            if Instant::now() >= ready_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Job Object child did not report ready");
            }
            thread::sleep(Duration::from_millis(10));
        }

        drop(containment);
        let termination_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().expect("poll child").is_some() {
                return;
            }
            if Instant::now() >= termination_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("closing the Job Object did not terminate the child");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
