# toolfence

Security audit for MCP servers and agent tool-chains. Read-only: it never
executes the code it scans and never calls `tools/call`.

```bash
toolfence https://github.com/owner/repo     # scan a repo (extracts tools from source)
toolfence ./path/to/server                  # scan a local checkout
toolfence tools.json                        # scan a tools/list export
toolfence --endpoint https://host/mcp       # live server — calls tools/list only
```

Or in CI, where it runs on every pull request:

```yaml
- uses: dhb520cat/toolfence@v0
  with:
    fail-on: critical
```

Findings land in the job summary, and `findings` / `critical` / `tools` are
exposed as step outputs.

It is also an MCP server, so an agent can audit a server before trusting it:

```json
{ "mcpServers": { "toolfence": {
    "command": "python3", "args": ["-m", "toolfence.server"] } } }
```

Three tools — `scan_repository`, `scan_tool_manifest`, `explain_rule`. All three
are read-only, declare `readOnlyHint: true` and `destructiveHint: false`, take no
credentials, and **pass toolfence's own audit with zero findings**. A test asserts
that they keep doing so.

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

A survey of 30 repositories drawn from `punkpeye/awesome-mcp-servers`
(3,877 entries, filtered to non-archived TS/JS/Python/Go projects by stars).
21 of them yielded extractable tools — **1,666 tools in total**.

```
critical   17    high   96    medium  135    low   20
```

7 of 21 repositories come back completely clean.

Every remaining critical is an irreversible delete against something that
matters, with no confirmation affordance in the tool itself:

```
awslabs/mcp                   delete_db_cluster, delete_db_instance
                              delete_fhir_resource        (health records)
                              delete_instance_in_study    (medical imaging)
                              mcp_delete_ecs_infrastructure
containers/kubernetes-mcp     resources_delete
cloudflare/mcp-server         container_file_delete
txn2/kubefwd                  remove_namespace, remove_service
```

Two `INJECTION_SURFACE` findings are real text shipped by github-mcp-server:
*"**always call this tool** when the user asks for details about…"*. Not a
vulnerability — a pattern worth naming, since a description that issues orders
goes verbatim into the model's context.

**This is a count of patterns, not a list of vulnerabilities.** Most of these
projects delegate confirmation to the client, which is where MCP's design puts
it. What the number says is that the tool layer itself carries no guardrail —
swap in a client that doesn't prompt, and the delete goes through.

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
- Python signatures are parsed for parameter names. Without them every Python
  tool looked unguarded; `awslabs/mcp`'s `delete_resource` actually takes a
  `confirmed` parameter, and the scanner was calling it unprotected.
- `credentials_token` described as coming *"from get_aws_session_info()"* is a
  handle, not a secret in transit.
- ZWNJ (U+200C) is Persian and Arabic orthography, not a hidden-instruction
  marker. Flagging it fired on every project shipping RTL translations.
- **Severity follows the object, not the verb.** `folder_remove_motion_blur`
  is not `delete_db_cluster`. Grading destructive tools by what they act on cut
  false criticals by 76% (72 → 17) across the survey.

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
pip install git+https://github.com/dhb520cat/toolfence
toolfence --help
```

No dependencies outside the standard library. Python 3.10+.

`--json` for machine output. `--fail-on {critical,high,medium,low,never}` sets the
exit code, so it drops into CI as-is.

## Tests

```bash
python3 test_toolfence.py      # 68 assertions, 25 true negatives, plus a self-audit
```

MIT.
