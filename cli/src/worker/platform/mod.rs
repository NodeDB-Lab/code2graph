// SPDX-License-Identifier: Apache-2.0

//! Platform-specific worker containment.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{configure_command, contain, terminate};
#[cfg(windows)]
pub use windows::{configure_command, contain, terminate};
