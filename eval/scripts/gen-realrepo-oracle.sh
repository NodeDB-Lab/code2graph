#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate the real-repository SCIP-oracle corpus used by the eval scorecard.
#
# This is a MAINTAINER tool (like `oracle-regen`): it fetches pinned third-party
# repositories, runs their language's external SCIP indexer, and writes a
# `*_realrepo/<case>/` corpus dir under `eval/corpus/` — which is gitignored, so
# nothing third-party is vendored. `cargo run -p code2graph-eval` then scores it
# automatically (its row appears alongside the committed micro-fixtures). The
# published numbers live in `eval/REAL-REPO-SCORECARD.md`.
#
# Prerequisites on PATH: git, rust-analyzer (with the `scip` subcommand),
# and `cargo` in this workspace. Network access to fetch the pinned repos.
#
# Usage:  eval/scripts/gen-realrepo-oracle.sh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
corpus="$repo_root/eval/corpus"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ── Case: anyhow (real mid-size Rust crate, ~3.9k LOC, near-zero deps) ────────
gen_rust_case() {
  local name="$1" url="$2" ref="$3"
  local case_dir="$corpus/rust_realrepo/$name"
  echo "== rust_realrepo/$name : cloning $url @ $ref"
  git clone --quiet "$url" "$work/$name"
  git -C "$work/$name" checkout --quiet "$ref"

  echo "== indexing with rust-analyzer scip (relative_path = src/…)"
  ( cd "$work/$name" && rust-analyzer scip . >/dev/null 2>&1 )

  echo "== assembling corpus case (src/ only, paths matching SCIP)"
  rm -rf "$case_dir"
  mkdir -p "$case_dir/src"
  # Mirror the src/ tree so on-disk case-relative paths equal SCIP relative_path.
  ( cd "$work/$name/src" && find . -name '*.rs' -print0 \
      | while IFS= read -r -d '' f; do
          mkdir -p "$case_dir/src/$(dirname "$f")"
          cp "$f" "$case_dir/src/$f"
        done )
  cp "$work/$name/index.scip" "$case_dir/index.scip"

  echo "== deriving oracle.edges from index.scip"
  ( cd "$repo_root" && cargo run -q -p code2graph-eval \
      --features oracle-regen --bin gen-oracle -- "$case_dir" )

  echo "== scoping oracle to intra-src ref→def pairs (both endpoints under src/)"
  local hdr="# oracle: SCIP ($name $ref) — intra-src location pairs (ref -> def), role-agnostic"
  { echo "$hdr"
    awk 'NF==2 && $1 ~ /^src\// && $2 ~ /^src\//' "$case_dir/oracle.edges"
  } > "$case_dir/oracle.edges.tmp"
  mv "$case_dir/oracle.edges.tmp" "$case_dir/oracle.edges"
  echo "== $name: $(($(wc -l < "$case_dir/oracle.edges") - 1)) intra-src oracle edges"
}

# ── Case: a real TypeScript project (indexed with scip-typescript) ───────────
# `src_dir` is the project's TS source root (scip relative_path is project-root
# relative, so we mirror it verbatim and scope the oracle to intra-<src_dir>).
gen_ts_case() {
  local name="$1" url="$2" ref="$3" src_dir="$4"
  local case_dir="$corpus/ts_realrepo/$name"
  echo "== ts_realrepo/$name : cloning $url @ $ref"
  git clone --quiet "$url" "$work/$name"
  git -C "$work/$name" checkout --quiet "$ref"

  echo "== npm install (needed for scip-typescript cross-file resolution)"
  ( cd "$work/$name" && npm install --no-audit --no-fund --silent >/dev/null 2>&1 )

  echo "== indexing with scip-typescript"
  ( cd "$work/$name" && npx --yes @sourcegraph/scip-typescript@latest index \
      --output index.scip >/dev/null 2>&1 )

  echo "== assembling corpus case ($src_dir/ only, paths matching SCIP)"
  rm -rf "$case_dir"
  mkdir -p "$case_dir/$src_dir"
  ( cd "$work/$name/$src_dir" && find . -name '*.ts' -not -path '*/test*' -print0 \
      | while IFS= read -r -d '' f; do
          mkdir -p "$case_dir/$src_dir/$(dirname "$f")"
          cp "$f" "$case_dir/$src_dir/$f"
        done )
  cp "$work/$name/index.scip" "$case_dir/index.scip"

  echo "== deriving + scoping oracle to intra-$src_dir ref→def pairs"
  ( cd "$repo_root" && cargo run -q -p code2graph-eval \
      --features oracle-regen --bin gen-oracle -- "$case_dir" )
  local hdr="# oracle: SCIP ($name $ref) — intra-$src_dir location pairs (ref -> def), role-agnostic"
  { echo "$hdr"
    awk -v d="^$src_dir/" 'NF==2 && $1 ~ d && $2 ~ d' "$case_dir/oracle.edges"
  } > "$case_dir/oracle.edges.tmp"
  mv "$case_dir/oracle.edges.tmp" "$case_dir/oracle.edges"
  echo "== $name: $(($(wc -l < "$case_dir/oracle.edges") - 1)) intra-$src_dir oracle edges"
}

gen_rust_case anyhow https://github.com/dtolnay/anyhow.git 1.0.104
gen_ts_case ky https://github.com/sindresorhus/ky.git \
  3419113b48e034fdcf8fa6bd3be3da7b3d0d758f source

echo
echo "Done. Score with:  cargo run -p code2graph-eval"
echo "(the rust_realrepo row scores code2graph resolution vs the SCIP oracle)"
