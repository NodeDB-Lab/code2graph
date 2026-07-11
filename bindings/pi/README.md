# @nodedb-lab/pi-code2graph

Deterministic structural code-graph tools for [Pi Coding Agent](https://pi.dev). It scans local source into symbols, references, and confidence-tagged edges without uploading source or storing a project index.

## Install

```sh
pi install npm:@nodedb-lab/pi-code2graph
# Try for one session without changing settings:
pi -e npm:@nodedb-lab/pi-code2graph
```

Requires Pi and Node.js 22+. The native dependency supports Linux x64/arm64 (glibc), Linux x64 musl, macOS x64/arm64, and Windows x64. CI executes the host addon on Ubuntu, macOS, and Windows; Linux arm64 and musl artifacts are cross-built and package-validated by the release workflow because they are not runnable on the hosted x64 runner. Update with `pi update npm:@nodedb-lab/pi-code2graph`; remove with `pi remove npm:@nodedb-lab/pi-code2graph`.

## Use

Ask Pi to scan or search before broad text exploration. The extension provides:

- `code2graph_scan` — bounded source scan and graph summary.
- `code2graph_symbol_search` — search definitions by name, signature, kind, or file.
- `code2graph_callers` / `code2graph_callees` — indexed relations.
- `code2graph_impact` — bounded reverse-impact traversal.

Commands: `/code2graph status`, `/code2graph scan [path]`, and `/code2graph symbols [query]`.

Search results return a lossless `id` object. Pass its JSON value as `symbolId` to relation and impact tools for an exact target; text queries can be ambiguous and are explicitly marked as such.

## Safety, limits, and accuracy

The extension reads source under the explicitly selected root using the Pi process's permissions; native extensions run with the same privileges as Pi. Review packages before installation. It honors `.gitignore` and `.ignore`, never follows directory symlinks, and always excludes dependency/build directories. Scans are cancellable, cache only a bounded number of snapshots, and cap files (1,000), a source file (1 MB), total source (25 MB), and traversal depth (32). `refresh: true` forces a new snapshot.

Edges carry a confidence. Name-tier resolution is recall-first and can be ambiguous; scope-tier resolution is more precise where supported but remains syntactic, not type-checker complete.

If native loading fails, reinstall without omitting optional dependencies:

```sh
npm install @nodedb-lab/pi-code2graph
```

## Development

```sh
# Before the required core version is published, CI stages a packed local core
# artifact and intentionally does not use a source lockfile that would falsely
# resolve an older registry binary.
npm install
npm run test:all
```

The published manifest always names the tested registry core range. Release CI regenerates its lockfile in an isolated staging directory only after that exact core version is available, then packs and smoke-tests the resulting tarball.

Apache-2.0.
