// SPDX-License-Identifier: Apache-2.0

//! Project selection and project-relative path contracts.

mod manifest;
mod path;
mod select;

pub use path::ProjectPath;
pub use select::{ProjectSelection, SelectionProvenance, select_project};
