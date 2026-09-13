"""toolfence 的 MCP server 形态。

把审计能力暴露成 MCP 工具,让别的 agent 能直接调用。

设计上的自我约束 —— 这个 server 必须能通过它自己的审计:
  · 三个工具全部只读,没有任何破坏性操作
  · 每个都标 readOnlyHint: true / destructiveHint: false
  · 不接受凭证参数(GitHub token 从环境读,不经过模型)
  · 作用域在描述里明确声明
  · 描述只说明行为,不对模型下命令
"""
from __future__ import annotations

import json
import sys

from . import scan as S
from .cli import from_github

PROTOCOL = "2024-11-05"

TOOLS = [
    {
        "name": "scan_repository",
        "description": (
            "Audit a public GitHub repository's MCP tool definitions and return "
            "structured findings. Extracts tools from TypeScript, JavaScript, "
            "Python and Go source, then applies seven rules covering unguarded "
            "destructive operations, annotation mismatches, injection surface in "
            "tool descriptions, hidden instructions aimed at automated systems, "
            "personal data in parameters, credentials in parameters, and "
            "unbounded scope. Read-only: clones nothing, executes nothing, and "
            "never calls tools/call on the audited server. Operates only on the "
            "repository named in the argument."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository_url": {
                    "type": "string",
                    "description": "A github.com repository URL, e.g. https://github.com/owner/name",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Omit findings below this severity. Defaults to low.",
                },
            },
            "required": ["repository_url"],
        },
        "annotations": {
            "title": "Scan a repository",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "scan_tool_manifest",
        "description": (
            "Audit a tools/list response that you already have, without any "
            "network access. Accepts the JSON-RPC result object, a bare list of "
            "tool definitions, or the tools array itself. Use this to check a "
            "server you are already connected to. Read-only and offline."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "object",
                    "description": "A tools/list result, or {\"tools\": [...]}",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Omit findings below this severity. Defaults to low.",
                },
            },
            "required": ["manifest"],
        },
        "annotations": {
            "title": "Scan a manifest",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "explain_rule",
        "description": (
            "Return the reasoning behind one of the seven rules: what it detects, "
            "why it matters, the audit it came from, and what it deliberately "
            "does not fire on. Offline and read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule": {
                    "type": "string",
                    "enum": ["DESTRUCTIVE_NO_CONFIRM", "ANNOTATION_MISMATCH",
                             "INJECTION_SURFACE", "HONEYPOT", "PII_EXPOSURE",
                             "CREDENTIAL_IN_PARAM", "UNBOUNDED_SCOPE"],
                    "description": "The rule identifier, as it appears in findings.",
                },
            },
            "required": ["rule"],
        },
        "annotations": {
            "title": "Explain a rule",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
]

RULE_NOTES = {
    "DESTRUCTIVE_NO_CONFIRM": {
        "detects": "Destructive or outward-facing tools with no confirmation affordance in the tool itself.",
        "why": "MCP leaves confirmation to the client. A tool with no affordance of its own is safe only "
               "for as long as every client that mounts it prompts. Swap the client and the delete goes through.",
        "origin": "Mermail gates destructive tools behind a single-use confirmationToken obtained from "
                  "prepare_destructive_action. That is the shape this rule looks for.",
        "does_not_fire_on": "Tools carrying a confirm/token/dry_run parameter, tools declaring "
                            "readOnlyHint or destructiveHint:false, and read verbs in the head position "
                            "(get_create_fields is a read). Severity follows the object: deleting a "
                            "database cluster is critical, removing a video effect is not.",
    },
    "ANNOTATION_MISMATCH": {
        "detects": "A tool declaring readOnlyHint:true or destructiveHint:false whose name says otherwise.",
        "why": "Callers auto-approve on these hints. A wrong hint is a false safety guarantee, which is "
               "worse than no hint at all.",
        "origin": "The MCP specification's own tool annotations.",
        "does_not_fire_on": "Write-tier verbs — only irreversible and outward-facing ones conflict.",
    },
    "INJECTION_SURFACE": {
        "detects": "Imperative language inside tool descriptions.",
        "why": "Descriptions reach the model verbatim. A description that issues orders means anyone who "
               "can edit it can steer the agent.",
        "origin": "Observed in shipped code: github-mcp-server's notification tools say "
                  "'always call this tool when asked what to work on next'.",
        "does_not_fire_on": "Descriptions that merely describe behaviour, however long.",
    },
    "HONEYPOT": {
        "detects": "Instructions hidden from human readers but visible to machines — HTML comments, "
                   "zero-width characters — that demand the agent's own system prompt.",
        "why": "Measured in 2026: 73.2% of agent-bounty repositories carry one, typically asking the "
               "agent to paste its system prompt into a public pull request.",
        "origin": "A survey of Algora GitHub bounties.",
        "does_not_fire_on": "Ordinary HTML comments, '### System Prompt' section headings, install "
                            "instructions saying 'paste this in your configuration file', and ZWNJ in "
                            "Persian, Arabic or Urdu text, where it is orthography rather than concealment.",
    },
    "PII_EXPOSURE": {
        "detects": "Tool parameters named after personal data.",
        "why": "Tool arguments persist in conversation history, logs and telemetry.",
        "origin": "Ported from a TEE contract's PII guard, which blocked personal data from reaching an "
                  "enclave that had no business holding it.",
        "does_not_fire_on": "Nothing yet — this rule is name-based and deliberately conservative.",
    },
    "CREDENTIAL_IN_PARAM": {
        "detects": "Secrets passed as tool arguments.",
        "why": "The model should never handle a credential. Servers can read them from the environment.",
        "origin": "Standard practice, violated often.",
        "does_not_fire_on": "Reference handles — a token whose description says where it came from "
                            "('from get_aws_session_info()', 'returned by', 'single-use') proves a session "
                            "rather than carrying a secret.",
    },
    "UNBOUNDED_SCOPE": {
        "detects": "Arbitrary path, URL, command or SQL in a tool's surface.",
        "why": "Path traversal, SSRF and injection, respectively.",
        "origin": "Standard practice.",
        "does_not_fire_on": "Tools that declare their boundary — 'only searches within allowed "
                            "directories' is a bounded scope, not an unbounded one.",
    },
}

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _filter(findings, min_sev):
    if not min_sev:
        return findings
    cap = _ORDER.get(min_sev, 3)
    return [f for f in findings if _ORDER.get(f.severity, 9) <= cap]


def _report(findings, target, n_tools):
    findings = S.sort_findings(findings)
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "target": target,
        "tools_found": n_tools,
        "summary": counts or {"clean": True},
        "findings": [f.as_dict() for f in findings],
        "note": ("tools_found of 0 means no tool definitions could be extracted — "
                 "an unsupported language, or sources that live outside the repository. "
                 "It does not mean the server is clean."),
    }


def call_tool(name: str, args: dict) -> dict:
    if name == "scan_repository":
        url = (args or {}).get("repository_url") or ""
        if "github.com/" not in url:
            raise ValueError("repository_url must be a github.com URL")
        tools, findings = from_github(url)
        by_src = {}
        for t in tools:
            by_src.setdefault(t.get("_source", "tools/list"), []).append(t)
        for src, group in by_src.items():
            findings += S.scan_tools(group, src)
        return _report(_filter(findings, (args or {}).get("min_severity")), url, len(tools))

    if name == "scan_tool_manifest":
        m = (args or {}).get("manifest")
        if isinstance(m, dict):
            tools = (m.get("result") or {}).get("tools") or m.get("tools") or []
        elif isinstance(m, list):
            tools = m
        else:
            raise ValueError("manifest must be an object or a list")
        if not isinstance(tools, list):
            raise ValueError("could not find a tools array in manifest")
        findings = S.scan_tools(tools, "manifest")
        return _report(_filter(findings, (args or {}).get("min_severity")),
                       "manifest", len(tools))

    if name == "explain_rule":
        rule = (args or {}).get("rule")
        if rule not in RULE_NOTES:
            raise ValueError(f"unknown rule: {rule}")
        return {"rule": rule, **RULE_NOTES[rule]}

    raise ValueError(f"unknown tool: {name}")


def handle(req: dict) -> dict | None:
    rid, method = req.get("id"), req.get("method")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "toolfence", "version": "0.2.0"},
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = req.get("params") or {}
        try:
            out = call_tool(p.get("name"), p.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(out, ensure_ascii=False, indent=1)}],
                "isError": False,
            }}
        except SystemExit as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": str(e)}], "isError": True}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                "isError": True}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> int:
    """stdio transport: 一行一个 JSON-RPC 消息。"""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
