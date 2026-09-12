# toolfence

Security audit for MCP servers and agent tool-chains. Read-only: it never
executes the code it scans and never calls `tools/call`.

```bash
toolfence https://github.com/owner/repo     # scan a repo (extracts tools from source)
toolfence ./path/to/server                  # scan a local checkout
toolfence tools.json                        # scan a tools/list export
toolfence --endpoint https://host/mcp       # live server — calls tools/list only
```

## Why

An agent with an inbox can be written to by anyone. An agent with a wallet can
move money. The tools in between decide how bad that gets, and right now almost
nobody audits them.

Every rule here came out of an actual audit, not a threat-modelling session:

| Rule | Where it came from |
|---|---|
| `DESTRUCTIVE_NO_CONFIRM` | Mermail gates destructive tools behind a single-use `confirmationToken`. Most servers gate nothing. |
| `ANNOTATION_MISMATCH` | MCP ships `readOnlyHint` / `destructiveHint`. A wrong hint is a *false* safety guarantee — callers auto-approve on it. |
| `INJECTION_SURFACE` | Tool descriptions land verbatim in the model's context. An imperative in a description is an instruction anyone who can edit it gets to give your agent. |
| `HONEYPOT` | 73.2% of agent-bounty repos hide instructions from humans (HTML comments) that tell automated systems to paste their system prompt into a public PR. |
| `PII_EXPOSURE` | Ported from a TEE contract's PII guard — the check that stops personal data reaching an enclave that shouldn't hold it. |
| `CREDENTIAL_IN_PARAM` | Tool arguments end up in conversation history, logs and telemetry. Secrets belong server-side. |
| `UNBOUNDED_SCOPE` | Arbitrary path / URL / command / SQL — traversal, SSRF, injection. |

## What it found

Measured, on public repositories:

```
github/github-mcp-server        114 tools   31 findings   4 critical, 2 high
sooperset/mcp-atlassian          62 tools    0 findings
executeautomation/mcp-playwright 37 tools    1 finding
mendableai/firecrawl-mcp-server  27 tools    2 findings   1 critical
modelcontextprotocol/servers     25 tools    5 findings   3 critical
upstash/context7                  7 tools    0 findings
```

272 tools across six repositories. Every critical is an irreversible delete with
no confirmation affordance — `delete_entities`, `delete_file`,
`delete_pending_pull_request_review`, `firecrawl_monitor_delete` and friends.

The two `INJECTION_SURFACE` findings are real text shipped by
github-mcp-server: *"**always call this tool** when the user asks for details
about…"*. That is not a vulnerability, it is a pattern worth naming — a
description that issues orders rather than describing behaviour, in a string
that goes verbatim into the model's context.

62 tools in mcp-atlassian produce zero findings. The rules don't fire at
everything that moves.

## Precision over recall

A scanner that flags everything is a scanner nobody reads. Three false positives
found during development are now regression tests:

- `list_emails` is not "send an email" — nouns that double as verbs only count in
  the verb slot.
- `get_create_fields` is a **read** — a read verb in the head position settles the
  whole name.
- `search_files` says *"Only searches within allowed directories"* — a declared
  boundary is not an unbounded scope.
- `"paste this in your configuration file"` in an install guide is not a honeypot.
  Only demands for the agent's **own** system prompt count.
- Test files, fixtures and examples are skipped entirely — `main_test.go` had a
  tool literally named `delete`.

Explicit annotations beat name inference: `create_directory` declares
`destructiveHint: false` and is believed.

## Limits

- **Lexical, not semantic.** It reads manifests and source text; it does not
  execute, type-check, or trace data flow.
- **TypeScript, JavaScript, Python and Go.** Other languages extract nothing —
  a clean report on a Rust server means the scanner found no tools, not that the
  server is clean. Tool count is printed so you can tell the difference.
- **`inputSchema: SomeZodSchema.shape`** hides parameter names; those tools are
  scanned on name and description alone.
- A clean report means *these seven rules did not fire*. It is not a safety
  certificate.

## Install

```bash
git clone https://github.com/dhb520cat/toolfence && cd toolfence
python3 -m toolfence.cli --help
```

No dependencies outside the standard library. Python 3.10+.

`--json` for machine output. `--fail-on {critical,high,medium,low,never}` sets the
exit code, so it drops into CI as-is.

## Tests

```bash
python3 test_toolfence.py      # 31 assertions, 12 of them true negatives
```

MIT.
