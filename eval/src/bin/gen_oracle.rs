// SPDX-License-Identifier: Apache-2.0

//! Regenerate `oracle.edges` from a committed `index.scip`.
//!
//! ```text
//! cargo run -p code2graph-eval --features oracle-regen --bin gen-oracle -- <case_dir>
//! ```
//!
//! Reads `<case_dir>/index.scip`, derives location-only ref→def pairs via the
//! SCIP reader, and writes `<case_dir>/oracle.edges` in the locked format:
//!
//! ```text
//! # oracle: SCIP index — location pairs (ref -> def), role-agnostic
//! alpha.ts:1 main.ts:4
//! ```

use std::fs;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: gen-oracle <case_dir>");
        process::exit(1);
    }

    let case_dir = Path::new(&args[1]);
    let scip_path = case_dir.join("index.scip");
    let out_path = case_dir.join("oracle.edges");

    let bytes = match fs::read(&scip_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", scip_path.display());
            process::exit(1);
        }
    };

    let edges = match code2graph_eval::oracle::oracle_edges_from_scip(&bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: failed to parse {}: {e}", scip_path.display());
            process::exit(1);
        }
    };

    let mut out = String::from(
        "# oracle: SCIP index \u{2014} location pairs (ref -> def), role-agnostic\n",
    );
    for (ref_file, ref_line, def_file, def_line) in &edges {
        out.push_str(&format!("{ref_file}:{ref_line} {def_file}:{def_line}\n"));
    }

    if let Err(e) = fs::write(&out_path, &out) {
        eprintln!("error: cannot write {}: {e}", out_path.display());
        process::exit(1);
    }

    println!("wrote {} edge(s) to {}", edges.len(), out_path.display());
}
