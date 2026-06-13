// SPDX-License-Identifier: Apache-2.0

//! Extraction: one tree-sitter pass per language → neutral [`FileFacts`].
//!
//! Each [`Extractor`] parses a single source file and emits symbol definitions
//! and references in a single walk. Extractors are pure and deterministic:
//! no I/O, no storage, no resolution.
//! Cross-file linking is the resolver's job ([`crate::resolve`]).
//!
//! [`FileFacts`]: crate::graph::FileFacts

mod dispatch;
mod support;

pub mod c;
pub mod cpp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod shell;
pub mod solidity;
pub mod swift;
pub mod typescript;

pub use dispatch::{Extractor, extract_file, extract_path};

pub use c::CExtractor;
pub use cpp::CppExtractor;
pub use go::GoExtractor;
pub use java::JavaExtractor;
pub use javascript::JavaScriptExtractor;
pub use kotlin::KotlinExtractor;
pub use php::PhpExtractor;
pub use python::PythonExtractor;
pub use ruby::RubyExtractor;
pub use rust::RustExtractor;
pub use shell::ShellExtractor;
pub use solidity::SolidityExtractor;
pub use swift::SwiftExtractor;
pub use typescript::TypeScriptExtractor;

pub(crate) use support::{
    child_text, collect_call_references, field_text, is_static, module_symbol, node_text,
    one_line_signature,
};
