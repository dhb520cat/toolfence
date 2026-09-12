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
modelcontextprotocol/servers    25 tools    5 findings   3 critical
sooperset/mcp-atlassian         62 tools    0 findings
upstash/context7                 7 tools    0 findings
executeautomation/mcp-playwright 37 tools   1 finding
mendableai/firecrawl-mcp-server 27 tools    2 findings   1 critical
```

All four criticals are irreversible deletes with no confirmation affordance
(`delete_entities`, `delete_observations`, `delete_relations`,
`firecrawl_monitor_delete`). 62 tools in mcp-atlassian produce zero findings —
the rules don't fire at everything that moves.

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

Explicit annotations beat name inference: `create_directory` declares
`destructiveHint: false` and is believed.

## Limits

- **Lexical, not semantic.** It reads manifests and source text; it does not
  execute, type-check, or trace data flow.
- **No Go support yet.** `github/github-mcp-server` extracts 0 tools. TypeScript,
  JavaScript and Python only.
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
python3 test_toolfence.py      # 19 assertions, 7 of them true negatives
```

MIT.
