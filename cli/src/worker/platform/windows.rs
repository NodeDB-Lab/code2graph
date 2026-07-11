// SPDX-License-Identifier: Apache-2.0

//! Windows Job Object containment.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JobObjectExtendedLimitInformation, SetInformationJobObject,
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

/// Assigns a child to a kill-on-close Job Object immediately after spawn.
pub fn contain(child: &mut Child) -> io::Result<Containment> {
    // SAFETY: null attributes/name create an unnamed Job Object.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let containment = Containment(job);
    let mut limits: JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: limits is correctly sized for this information class.
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: child handle remains valid while Child is alive.
    if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) } == 0 {
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
