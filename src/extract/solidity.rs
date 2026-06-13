// SPDX-License-Identifier: Apache-2.0

//! Solidity extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: declarations whose visibility is not `private`. Qualified
//! identity is derived from the file path (all directory segments kept, `.sol`
//! stripped from the last segment).
//!
//! Covered declaration kinds:
//! - `contract_declaration` → Class; `interface_declaration` → Interface;
//!   `library_declaration` → Class (Solidity libraries map naturally to class)
//! - `function_definition` (top-level → Function; inside contract → Method)
//! - `constructor_definition` (→ Method "constructor"; always emitted)
//! - `modifier_definition` (→ Method)
//! - `fallback_receive_definition` (→ Method "fallback"/"receive")
//! - `state_variable_declaration` (→ Static; `constant`/`immutable` → Const)
//! - `constant_variable_declaration` (file-level → Const)
//! - `event_definition` (→ Other)
//! - `error_declaration` (→ Other)
//! - `struct_declaration` (→ Struct; members → Static)
//! - `enum_declaration` (→ Enum; values → Const)
//! - `user_defined_type_definition` (`type X is Y`) → TypeAlias
//!
//! Skipped: `pragma_directive`, `import_directive`, `using_directive`.
//!
//! References: callee identifiers captured by two call patterns. The grammar's
//! `call_expression` wraps its callee in a visible `expression` node:
//! - free call `foo()` → `(call_expression (expression (identifier) @callee))`
//! - member call `x.foo()` → `(call_expression (expression (member_expression property: (identifier) @callee)))`
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, collect_call_references, field_text, node_text, one_line_signature};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier inside the call's `expression` child.
/// Pattern 2: member call `x.foo()` — member_expression's `property` field is the callee.
const CALL_QUERY: &str = r#"
[
  (call_expression (expression (identifier) @callee))
  (call_expression (expression (member_expression property: (identifier) @callee)))
]
"#;

/// Extracts Solidity symbols and references.
pub struct SolidityExtractor;

impl Extractor for SolidityExtractor {
    fn lang(&self) -> Language {
        Language::Solidity
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_solidity::LANGUAGE);
        let mut parser = Parser::new();
        parser
            .set_language(&ts_language)
            .map_err(|_| CodegraphError::Parse {
                path: file.to_owned(),
            })?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| CodegraphError::Parse {
                path: file.to_owned(),
            })?;

        let root = tree.root_node();
        let bytes = source.as_bytes();

        let ns_strings = solidity_namespaces(file);
        let ns_descriptors: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut symbols = Vec::new();
        collect_decls(root, &ns_descriptors, false, bytes, file, &mut symbols);
        symbols.push(super::module_symbol(
            Language::Solidity,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Solidity,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Solidity.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Namespace descriptors derived purely from the file path.
///
/// Strip `.sol` from the last segment, split on `/`, filter empty segments —
/// all directory segments are kept (no `src/` stripping). For example,
/// `contracts/Token.sol` → `["contracts", "Token"]`.
fn solidity_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".sol").unwrap_or(file);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Visibility gate ──────────────────────────────────────────────────────────

/// Returns `true` if a declaration should be emitted (not `private`).
///
/// Scans direct children for a node of kind `visibility`. If that node's text
/// is `"private"` the declaration is suppressed; any other value (public,
/// external, internal) or the absence of a visibility node → emit.
/// Recall-first — only `private` is filtered.
fn is_visible(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "visibility" {
            return node_text(&child, bytes) != "private";
        }
    }
    // No visibility child → default visibility → emit.
    true
}

// ── Symbol builder ───────────────────────────────────────────────────────────

/// Build a [`Symbol`] and push it onto `out`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    node: &Node,
    name: String,
    kind: SymbolKind,
    descriptors: Vec<Descriptor>,
    bytes: &[u8],
    file: &str,
) {
    out.push(Symbol {
        id: SymbolId::global(Language::Solidity.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });
}

/// Emit a container (contract/interface/library) Type symbol and recurse into its body.
fn emit_container_and_body(
    out: &mut Vec<Symbol>,
    node: Node,
    type_name: String,
    kind: SymbolKind,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
) {
    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        kind,
        type_descriptors.clone(),
        bytes,
        file,
    );

    // Recurse into `contract_body` (field "body").
    if let Some(body) = node.child_by_field_name("body") {
        collect_decls(body, &type_descriptors, true, bytes, file, out);
    }
}

// ── Declaration collection ───────────────────────────────────────────────────

/// Collect definitions from a container node (source_file or contract_body).
///
/// `prefix` is the descriptor list up to (but not including) the current level.
/// `inside_type` is true when we are inside a contract/interface/library body,
/// which drives `function_definition` → Method vs. Function.
fn collect_decls(
    container: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "contract_declaration" | "library_declaration" => {
                handle_container(child, SymbolKind::Class, prefix, bytes, file, out);
            }
            "interface_declaration" => {
                handle_container(child, SymbolKind::Interface, prefix, bytes, file, out);
            }
            "function_definition" => {
                handle_function(child, prefix, inside_type, bytes, file, out);
            }
            "constructor_definition" => {
                handle_constructor(child, prefix, bytes, file, out);
            }
            "modifier_definition" => {
                handle_modifier(child, prefix, bytes, file, out);
            }
            "fallback_receive_definition" => {
                handle_fallback_receive(child, prefix, bytes, file, out);
            }
            "state_variable_declaration" => {
                handle_state_variable(child, prefix, bytes, file, out);
            }
            "constant_variable_declaration" => {
                handle_constant_variable(child, prefix, bytes, file, out);
            }
            "event_definition" | "error_declaration" => {
                handle_event_or_error(child, prefix, bytes, file, out);
            }
            "struct_declaration" => {
                handle_struct(child, prefix, bytes, file, out);
            }
            "enum_declaration" => {
                handle_enum(child, prefix, bytes, file, out);
            }
            "user_defined_type_definition" => {
                handle_typedef(child, prefix, bytes, file, out);
            }
            // pragma_directive, import_directive, using_directive → skip
            _ => {}
        }
    }
}

/// Handle `contract_declaration`, `interface_declaration`, `library_declaration`.
fn handle_container(
    node: Node,
    kind: SymbolKind,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Containers have no visibility keyword themselves, but be defensive.
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    emit_container_and_body(out, node, type_name, kind, prefix, bytes, file);
}

/// Handle `function_definition`.
///
/// `inside_type` → SymbolKind::Method with Descriptor::Method; otherwise
/// SymbolKind::Function with Descriptor::Method (Solidity free functions are
/// still callable, so Method descriptor is correct).
fn handle_function(
    node: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let kind = if inside_type {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    push_symbol(out, &node, name, kind, descriptors, bytes, file);
}

/// Handle `constructor_definition` (no name field → always "constructor").
fn handle_constructor(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Constructors are always emitted; no visibility gate.
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: "constructor".to_owned(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        "constructor".to_owned(),
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `modifier_definition`.
fn handle_modifier(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `fallback_receive_definition`.
///
/// There is no name field; the leading keyword in the raw text determines the
/// name: starts with "fallback" → "fallback", "receive" → "receive".
/// If neither can be determined the node is skipped.
fn handle_fallback_receive(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let text = node_text(&node, bytes).trim_start();
    let name = if text.starts_with("fallback") {
        "fallback"
    } else if text.starts_with("receive") {
        "receive"
    } else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.to_owned(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        name.to_owned(),
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `state_variable_declaration`.
///
/// Visibility is the named field `visibility`. If its text is `"private"`, skip.
/// Kind: Const if node has an `immutable` child or the text contains the word
/// `constant`; otherwise Static.
fn handle_state_variable(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Visibility gate: use the named field `visibility` on this node type.
    if let Some(vis) = node.child_by_field_name("visibility") {
        if node_text(&vis, bytes) == "private" {
            return;
        }
    }

    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    // Determine kind: immutable child present, or text contains "constant".
    let has_immutable = node
        .children(&mut node.walk())
        .any(|c| c.kind() == "immutable");
    let text = node_text(&node, bytes);
    let is_constant = has_immutable || text.split_whitespace().any(|w| w == "constant");

    let kind = if is_constant {
        SymbolKind::Const
    } else {
        SymbolKind::Static
    };

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(out, &node, name, kind, descriptors, bytes, file);
}

/// Handle `constant_variable_declaration` (file-level `uint constant X = 1;`).
fn handle_constant_variable(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Const,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `event_definition` and `error_declaration` (both → Term / Other).
fn handle_event_or_error(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Other,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `struct_declaration`.
///
/// Emits a Struct Type symbol, then descends into `struct_body` to emit each
/// `struct_member` as a Term/Static nested under the struct.
fn handle_struct(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        SymbolKind::Struct,
        type_descriptors.clone(),
        bytes,
        file,
    );

    // Descend into struct_body for members.
    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for member in body.children(&mut cursor) {
        if member.kind() != "struct_member" {
            continue;
        }
        let member_name = match field_text(&member, "name", bytes) {
            Some(n) => n,
            None => continue,
        };
        let mut member_descriptors = type_descriptors.clone();
        member_descriptors.push(Descriptor::Term(member_name.clone()));
        push_symbol(
            out,
            &member,
            member_name,
            SymbolKind::Static,
            member_descriptors,
            bytes,
            file,
        );
    }
}

/// Handle `enum_declaration`.
///
/// Emits an Enum Type symbol, then descends into `enum_body` to emit each
/// `enum_value` as a Term/Const nested under the enum.
fn handle_enum(node: Node, prefix: &[Descriptor], bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        SymbolKind::Enum,
        type_descriptors.clone(),
        bytes,
        file,
    );

    // Descend into enum_body for values.
    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for value_node in body.children(&mut cursor) {
        if value_node.kind() != "enum_value" {
            continue;
        }
        // enum_value is a leaf named node; its text is the case name.
        let value_name = node_text(&value_node, bytes).to_owned();
        if value_name.is_empty() {
            continue;
        }
        let mut value_descriptors = type_descriptors.clone();
        value_descriptors.push(Descriptor::Term(value_name.clone()));
        push_symbol(
            out,
            &value_node,
            value_name,
            SymbolKind::Const,
            value_descriptors,
            bytes,
            file,
        );
    }
}

/// Handle `user_defined_type_definition` (`type X is uint;`).
fn handle_typedef(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::TypeAlias,
        descriptors,
        bytes,
        file,
    );
}

// ── Inheritance-edge helpers ─────────────────────────────────────────────────

/// Recursively walk `node` collecting `Inherit` references for every
/// `contract_declaration` and `interface_declaration` in the tree.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "contract_declaration" | "interface_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    if let Some(ancestor) = child.child_by_field_name("ancestor") {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&ancestor, bytes), "."),
                            &ancestor,
                            file,
                            RefRole::Inherit,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested contracts/interfaces are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, path: &str) -> FileFacts {
        SolidityExtractor.extract(src, path).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // Test 1: contract with public function and private function → visibility gate.
    #[test]
    fn contract_visibility_gate() {
        let src = r#"
pragma solidity ^0.8.0;
contract Token {
    function mint(address to) public {}
    function _secret() private {}
}
"#;
        let facts = extract(src, "contracts/Token.sol");

        let token = by_name(&facts, "Token").unwrap();
        assert_eq!(token.kind, SymbolKind::Class);
        assert_eq!(
            token.id.to_scip_string(),
            "codegraph    contracts/Token/Token#"
        );

        let mint = by_name(&facts, "mint").unwrap();
        assert_eq!(mint.kind, SymbolKind::Method);
        assert_eq!(
            mint.id.to_scip_string(),
            "codegraph    contracts/Token/Token#mint()."
        );

        // private function must NOT be emitted
        assert!(by_name(&facts, "_secret").is_none());
    }

    // Test 2: interface → SymbolKind::Interface; library → SymbolKind::Class.
    #[test]
    fn interface_and_library_kinds() {
        let src = r#"
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
}
"#;
        let facts = extract(src, "contracts/Defs.sol");

        let iface = by_name(&facts, "IERC20").unwrap();
        assert_eq!(iface.kind, SymbolKind::Interface);
        assert_eq!(
            iface.id.to_scip_string(),
            "codegraph    contracts/Defs/IERC20#"
        );

        let lib = by_name(&facts, "SafeMath").unwrap();
        assert_eq!(lib.kind, SymbolKind::Class);
        assert_eq!(
            lib.id.to_scip_string(),
            "codegraph    contracts/Defs/SafeMath#"
        );
    }

    // Test 3: state variable (public) → Static; `constant` → Const.
    #[test]
    fn state_variable_kinds() {
        let src = r#"
pragma solidity ^0.8.0;
contract Store {
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000;
}
"#;
        let facts = extract(src, "src/Store.sol");

        let total = by_name(&facts, "totalSupply").unwrap();
        assert_eq!(total.kind, SymbolKind::Static);
        assert_eq!(
            total.id.to_scip_string(),
            "codegraph    src/Store/Store#totalSupply."
        );

        let max = by_name(&facts, "MAX_SUPPLY").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph    src/Store/Store#MAX_SUPPLY."
        );
    }

    // Test 3b: file-level constant_variable_declaration → Const.
    #[test]
    fn file_level_constant() {
        let src = r#"
pragma solidity ^0.8.0;
uint256 constant VERSION = 1;
"#;
        let facts = extract(src, "contracts/Const.sol");

        let ver = by_name(&facts, "VERSION").unwrap();
        assert_eq!(ver.kind, SymbolKind::Const);
        assert_eq!(
            ver.id.to_scip_string(),
            "codegraph    contracts/Const/VERSION."
        );
    }

    // Test 4: struct with members → Struct Type + Static members;
    //         enum with values → Enum Type + Const values.
    #[test]
    fn struct_and_enum() {
        let src = r#"
pragma solidity ^0.8.0;
contract Market {
    struct Item {
        uint256 price;
        address seller;
    }
    enum Status { Active, Sold, Cancelled }
}
"#;
        let facts = extract(src, "contracts/Market.sol");

        let item = by_name(&facts, "Item").unwrap();
        assert_eq!(item.kind, SymbolKind::Struct);
        assert_eq!(
            item.id.to_scip_string(),
            "codegraph    contracts/Market/Market#Item#"
        );

        let price = by_name(&facts, "price").unwrap();
        assert_eq!(price.kind, SymbolKind::Static);
        assert_eq!(
            price.id.to_scip_string(),
            "codegraph    contracts/Market/Market#Item#price."
        );

        let seller = by_name(&facts, "seller").unwrap();
        assert_eq!(seller.kind, SymbolKind::Static);

        let status = by_name(&facts, "Status").unwrap();
        assert_eq!(status.kind, SymbolKind::Enum);
        assert_eq!(
            status.id.to_scip_string(),
            "codegraph    contracts/Market/Market#Status#"
        );

        let active = by_name(&facts, "Active").unwrap();
        assert_eq!(active.kind, SymbolKind::Const);
        assert_eq!(
            active.id.to_scip_string(),
            "codegraph    contracts/Market/Market#Status#Active."
        );
    }

    // Test 5: event → Other; modifier → Method.
    #[test]
    fn event_and_modifier() {
        let src = r#"
pragma solidity ^0.8.0;
contract Vault {
    event Deposit(address indexed sender, uint256 amount);
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    address owner;
}
"#;
        let facts = extract(src, "contracts/Vault.sol");

        let ev = by_name(&facts, "Deposit").unwrap();
        assert_eq!(ev.kind, SymbolKind::Other);
        assert_eq!(
            ev.id.to_scip_string(),
            "codegraph    contracts/Vault/Vault#Deposit."
        );

        let modifier = by_name(&facts, "onlyOwner").unwrap();
        assert_eq!(modifier.kind, SymbolKind::Method);
        assert_eq!(
            modifier.id.to_scip_string(),
            "codegraph    contracts/Vault/Vault#onlyOwner()."
        );
    }

    // Test 6: free function at file level (no contract) → Function under namespace.
    #[test]
    fn free_function_top_level() {
        let src = r#"
pragma solidity ^0.8.0;
function computeHash(bytes memory data) pure returns (bytes32) {
    return keccak256(data);
}
"#;
        let facts = extract(src, "lib/Utils.sol");

        let func = by_name(&facts, "computeHash").unwrap();
        assert_eq!(func.kind, SymbolKind::Function);
        assert_eq!(
            func.id.to_scip_string(),
            "codegraph    lib/Utils/computeHash()."
        );
    }

    // Test 7: call references captured (free call + member call).
    #[test]
    fn call_references_captured() {
        let src = r#"
pragma solidity ^0.8.0;
contract Caller {
    function run() public {
        foo();
        x.bar();
    }
}
"#;
        let facts = extract(src, "contracts/Caller.sol");
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"foo"), "expected 'foo' in {names:?}");
        assert!(names.contains(&"bar"), "expected 'bar' in {names:?}");
    }

    #[test]
    fn lang_tag() {
        let facts = extract("pragma solidity ^0.8.0;", "contracts/Foo.sol");
        assert_eq!(facts.lang, "solidity");
    }

    // Test: contract with multiple bases → two Inherit refs.
    #[test]
    fn contract_multiple_inheritance() {
        let src = "pragma solidity ^0.8.0; contract Foo is Bar, Baz {}";
        let facts = extract(src, "contracts/Foo.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"Bar"), "expected 'Bar' in {inherit:?}");
        assert!(inherit.contains(&"Baz"), "expected 'Baz' in {inherit:?}");
    }

    // Test: interface extending another → one Inherit ref.
    #[test]
    fn interface_inheritance() {
        let src = "pragma solidity ^0.8.0; interface I is J {}";
        let facts = extract(src, "contracts/I.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"J"), "expected 'J' in {inherit:?}");
    }

    // Test: dotted library type in is-clause → leaf name only.
    #[test]
    fn dotted_parent_simple_name() {
        let src = "pragma solidity ^0.8.0; contract C is Lib.Base {}";
        let facts = extract(src, "contracts/C.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit.contains(&"Base"),
            "expected 'Base' (leaf of 'Lib.Base') in {inherit:?}"
        );
        assert!(
            !inherit.contains(&"Lib.Base"),
            "dotted form must not appear in {inherit:?}"
        );
    }
}
