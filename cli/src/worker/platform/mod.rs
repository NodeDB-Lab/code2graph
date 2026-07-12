// SPDX-License-Identifier: Apache-2.0

//! Platform-specific worker containment.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{Containment, KillHandle, configure_command, contain, kill_handle, terminate};
#[cfg(windows)]
pub use windows::{Containment, KillHandle, configure_command, contain, kill_handle, terminate};
