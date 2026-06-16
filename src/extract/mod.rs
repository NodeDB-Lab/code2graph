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

#[cfg(feature = "c")]
pub mod c;
#[cfg(feature = "cpp")]
pub mod cpp;
#[cfg(feature = "csharp")]
pub mod csharp;
#[cfg(feature = "dart")]
pub mod dart;
#[cfg(feature = "go")]
pub mod go;
#[cfg(feature = "hcl")]
pub mod hcl;
#[cfg(feature = "java")]
pub mod java;
#[cfg(feature = "typescript")]
pub mod javascript;
#[cfg(feature = "kotlin")]
pub mod kotlin;
#[cfg(feature = "lua")]
pub mod lua;
#[cfg(feature = "luau")]
pub mod luau;
#[cfg(feature = "pascal")]
pub mod pascal;
#[cfg(feature = "php")]
pub mod php;
#[cfg(feature = "python")]
pub mod python;
#[cfg(feature = "ruby")]
pub mod ruby;
#[cfg(feature = "rust")]
pub mod rust;
#[cfg(feature = "scala")]
pub mod scala;
#[cfg(feature = "shell")]
pub mod shell;
#[cfg(feature = "solidity")]
pub mod solidity;
#[cfg(feature = "sql")]
pub mod sql;
#[cfg(feature = "swift")]
pub mod swift;
#[cfg(feature = "typescript")]
pub mod typescript;

pub use dispatch::{Extractor, extract_file, extract_path};

#[cfg(feature = "c")]
pub use c::CExtractor;
#[cfg(feature = "cpp")]
pub use cpp::CppExtractor;
#[cfg(feature = "csharp")]
pub use csharp::CSharpExtractor;
#[cfg(feature = "dart")]
pub use dart::DartExtractor;
#[cfg(feature = "go")]
pub use go::GoExtractor;
#[cfg(feature = "hcl")]
pub use hcl::HclExtractor;
#[cfg(feature = "java")]
pub use java::JavaExtractor;
#[cfg(feature = "typescript")]
pub use javascript::JavaScriptExtractor;
#[cfg(feature = "kotlin")]
pub use kotlin::KotlinExtractor;
#[cfg(feature = "lua")]
pub use lua::LuaExtractor;
#[cfg(feature = "luau")]
pub use luau::LuauExtractor;
#[cfg(feature = "pascal")]
pub use pascal::PascalExtractor;
#[cfg(feature = "php")]
pub use php::PhpExtractor;
#[cfg(feature = "python")]
pub use python::PythonExtractor;
#[cfg(feature = "ruby")]
pub use ruby::RubyExtractor;
#[cfg(feature = "rust")]
pub use rust::RustExtractor;
#[cfg(feature = "scala")]
pub use scala::ScalaExtractor;
#[cfg(feature = "shell")]
pub use shell::ShellExtractor;
#[cfg(feature = "solidity")]
pub use solidity::SolidityExtractor;
#[cfg(feature = "sql")]
pub use sql::SqlExtractor;
#[cfg(feature = "swift")]
pub use swift::SwiftExtractor;
#[cfg(feature = "typescript")]
pub use typescript::TypeScriptExtractor;

#[allow(unused_imports)]
pub(crate) use support::{
    MIN_REF_LEN, attach_reference_scopes, child_text, collect_call_references, definition_bindings,
    field_text, import_bindings, innermost_scope, is_static, module_name, module_symbol,
    node_occurrence, node_span, node_text, one_line_signature, push_binding, push_import_ref,
    push_ref, push_scope, push_type_ref, simple_type_name, unquote,
};
