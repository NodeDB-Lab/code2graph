# Agent integration

How to make a coding agent actually reach for `c2g` — the code2graph CLI — instead of falling back to text search.

A capability an agent never invokes is worth nothing. Agents pick tools under uncertainty and default to the cheapest one they already trust — `grep`. A rule that asks the agent to first classify whether a question is "graph-shaped" loses that contest every time, because classifying is a judgement and grepping is not. Write the trigger as a fact the agent can check, not a call it has to make.

## The rule

Put this in the agent's instruction file — `CLAUDE.md`, `AGENTS.md`, a system prompt, or a host extension's tool description. Adjust the wording, keep the shape.

```markdown
## c2g (code2graph CLI)

`c2g` turns a codebase into a symbol/reference/edge graph for scope-precise,
cross-file navigation that grep cannot do.

**Trigger (mechanical, not a judgement call): the question names a code identifier**
— function, type, method, module. Whenever you are about to grep for a symbol name,
run a `c2g` query instead. Grep keeps everything that is NOT an identifier: log
strings, config values, comments, error text, non-source files, unsupported languages.

- `symbols <text>` / `def` — where it is defined, with kind, signature, and file:line
- `usages <sym>` / `callers` / `callees` — where it is used, who calls it, what it calls
- `impact <sym> --depth N` — blast radius: what transitively breaks if this changes
- `diff-impact [BASE]` — blast radius of the current git diff vs BASE
- `module-deps` — cross-file dependency edges; `references`/`imports <file>` — per-file edges

**Workflow** — index once, then query.

    c2g --root <dir> --allow-partial index
    c2g --root <dir> --allow-partial impact <sym> --depth 3

- ALWAYS pass `--allow-partial`: real codebases have files that fail extraction, and
  without it any such file aborts the command.
- ALWAYS pass `--root`: the implicit root is the working directory, and a home directory
  or filesystem root is refused because walking one costs minutes and describes no
  project.
- `--root` a single package for tight results, or the workspace root for cross-package
  questions. `--json` for machine-readable output.
- `--tier scope` (default) is precise; `--tier name` is recall-first; `--tier dense`
  unions all resolvers — filter on each edge's `Confidence`.
```

## Why it is written that way

**The trigger is a fact about the question.** "Does the question name an identifier?" has one answer the agent can read off the prompt. "Is this a graph-shaped question?" does not.

**There is no escape clause.** A rule that says *do not index for plain "where is X"* hands back the exact case code2graph answers better than grep: a definition lookup with kind, signature, and file:line, and no hits inside comments or string literals. An escape clause is easier to satisfy than the rule it guards, so the agent takes it.

**The boundary is by subject, not by question shape.** code2graph owns identifiers. Grep owns text that is not an identifier — log strings, config values, comments, error messages, files in languages with no extractor. Both keep a job; neither needs judgement to know which.

## Keep indexing cheap

An agent that pays a long setup cost before its first answer will not pay it twice. Two things keep that cost invisible:

- **Index freely.** The CLI caches per project. An unchanged source tree is served from the published snapshot without re-resolving, so re-running `index` on a clean tree is not a rebuild.
- **Query against the cache.** Queries read the stored graph. They do not re-extract.

If an agent host wraps the CLI, keep the same property: never make the agent wait for a full re-index to answer a question the cache already covers.

## Native host tools

A host that can register typed tools should do that instead of shelling out — the tool names sit in the agent's tool list on every turn, so selecting one costs the same as selecting a text search, and parameters are typed rather than string-assembled.

[`@nodedb-lab/pi-code2graph`](../bindings/pi) is a worked example: it registers scan, symbol search, callers/callees, and impact as typed tools, and chains them by passing a lossless symbol id from search into the relation queries so an ambiguous name never silently picks a target.

For hosts without an extension API, the CLI plus the rule above is the supported path.
