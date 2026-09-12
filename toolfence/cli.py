"""toolfence — MCP server / agent 工具链的安全审计器。

用法:
    toolfence https://github.com/owner/repo        # 扫仓库(含 honeypot)
    toolfence ./path/to/server                     # 扫本地目录
    toolfence tools.json                           # 扫 tools/list 导出
    toolfence --endpoint https://host/mcp          # 连活的 server,只调 tools/list

安全承诺:本工具从不执行被扫描的代码,从不调用 tools/call,
只读清单与文本。扫描一个仓库不会触发它的任何副作用。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

from . import scan as S
from .extract import from_source

UA = "toolfence/0.1 (+https://github.com/dhb520cat/toolfence)"
TEXT_EXT = {".md", ".markdown", ".txt", ".rst", ".yaml", ".yml", ".json"}
CODE_EXT = {".ts", ".js", ".tsx", ".mjs", ".py"}
MAX_TEXT = 400_000

# 只调这一个方法。工具自身的只读边界,与它检查的东西同一个标准。
ALLOWED_RPC = {"tools/list", "initialize"}


def _get(url: str, headers: dict | None = None, timeout: int = 40) -> bytes:
    req = urllib.request.Request(url, headers={"user-agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ------------------------------------------------------------------ 输入模式
def from_endpoint(url: str) -> tuple[list[dict], list[S.Finding]]:
    """连一个活的 MCP server,只调 tools/list。"""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"user-agent": UA, "content-type": "application/json",
                 "accept": "application/json, text/event-stream"},
    )
    with urllib.request.urlopen(req, timeout=40) as r:
        raw = r.read().decode("utf-8", "replace")
    # 有的 server 走 SSE
    if raw.lstrip().startswith("event:") or "\ndata: " in raw:
        for line in raw.splitlines():
            if line.startswith("data: "):
                raw = line[6:]
                break
    d = json.loads(raw)
    tools = (d.get("result") or {}).get("tools") or []
    return tools, []


def from_json_file(path: str) -> tuple[list[dict], list[S.Finding]]:
    d = json.load(open(path, encoding="utf-8"))
    if isinstance(d, list):
        return d, []
    tools = (d.get("result") or {}).get("tools") or d.get("tools") or []
    return tools, []


def _iter_local_texts(root: str):
    skip = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "target"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in TEXT_EXT | CODE_EXT:
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(p) > MAX_TEXT:
                        continue
                    yield os.path.relpath(p, root), open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue


def from_local(root: str) -> tuple[list[dict], list[S.Finding]]:
    findings, tools = [], []
    for rel, text in _iter_local_texts(root):
        findings += _scan_one(rel, text, tools)
    return tools, findings


def _scan_one(rel: str, text: str, tools: list) -> list:
    ext = os.path.splitext(rel)[1].lower()
    if ext in CODE_EXT:
        tools += from_source(text, rel)
        return []
    tools += _tools_from_text(rel, text)
    return S.scan_text(text, rel)


def from_github(url: str) -> tuple[list[dict], list[S.Finding]]:
    m = re.search(r"github\.com/([^/]+)/([^/#?]+)", url)
    if not m:
        raise SystemExit(f"不是 GitHub 仓库地址: {url}")
    owner, repo = m.group(1), m.group(2).removesuffix(".git")
    meta = json.loads(_get(f"https://api.github.com/repos/{owner}/{repo}",
                           {"accept": "application/vnd.github+json"}))
    branch = meta.get("default_branch", "main")
    blob = _get(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{branch}", timeout=120)

    findings, tools = [], []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or member.size > MAX_TEXT:
                continue
            rel = member.name.split("/", 1)[-1]
            if os.path.splitext(rel)[1].lower() not in TEXT_EXT | CODE_EXT:
                continue
            if any(part in rel.split("/") for part in ("node_modules", "dist", "build")):
                continue
            fh = tf.extractfile(member)
            if not fh:
                continue
            text = fh.read().decode("utf-8", "replace")
            findings += _scan_one(rel, text, tools)
    return tools, findings


def _tools_from_text(rel: str, text: str) -> list[dict]:
    """从 JSON 文件里认出 tools/list 形状的清单。"""
    if not rel.lower().endswith(".json"):
        return []
    try:
        d = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    cand = None
    if isinstance(d, dict):
        cand = (d.get("result") or {}).get("tools") or d.get("tools")
    elif isinstance(d, list):
        cand = d
    if not isinstance(cand, list) or not cand:
        return []
    if not all(isinstance(x, dict) and "name" in x for x in cand):
        return []
    for t in cand:
        t.setdefault("_source", rel)
    return cand


# -------------------------------------------------------------------- 输出
C = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
     "low": "\033[36m", "dim": "\033[2m", "off": "\033[0m", "b": "\033[1m"}


def render(findings: list[S.Finding], target: str, n_tools: int, use_color: bool) -> str:
    c = C if use_color else {k: "" for k in C}
    lines = [
        "",
        f"{c['b']}toolfence{c['off']} {c['dim']}— MCP / agent 工具链安全审计{c['off']}",
        f"{c['dim']}{'─' * 66}{c['off']}",
        f"  目标   {target}",
        f"  工具   {n_tools} 个",
    ]
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if findings:
        tally = "  ".join(
            f"{c[s]}{counts[s]} {s}{c['off']}"
            for s in ("critical", "high", "medium", "low") if s in counts
        )
        lines.append(f"  发现   {tally}")
    else:
        lines.append(f"  发现   {c['dim']}无{c['off']}")
    lines.append("")

    for f in S.sort_findings(findings):
        lines.append(f"{c[f.severity]}{c['b']}[{f.severity.upper()}]{c['off']} "
                     f"{c['b']}{f.rule}{c['off']}  {c['dim']}{f.where}{c['off']}")
        lines.append(f"  {f.summary}")
        if f.evidence:
            for ln in f.evidence.splitlines():
                lines.append(f"  {c['dim']}│ {ln[:110]}{c['off']}")
        if f.fix:
            body = f.fix
            while body:
                lines.append(f"  {c['dim']}→{c['off']} {body[:96]}")
                body = body[96:]
        lines.append("")

    if not findings:
        lines.append(f"  {c['dim']}未命中任何规则。这不等于安全——只说明这六类问题没出现。{c['off']}")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="toolfence",
        description="MCP server / agent 工具链的安全审计器(只读,不执行被扫描代码)",
    )
    ap.add_argument("target", nargs="?", help="GitHub 仓库地址 / 本地目录 / tools.json")
    ap.add_argument("--endpoint", help="活的 MCP server(仅调用 tools/list)")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--fail-on", default="critical",
                    choices=["critical", "high", "medium", "low", "never"],
                    help="达到该严重度时退出码非零(默认 critical)")
    a = ap.parse_args(argv)

    if not a.target and not a.endpoint:
        ap.error("需要一个 target 或 --endpoint")

    try:
        if a.endpoint:
            tools, findings = from_endpoint(a.endpoint)
            target = a.endpoint
        elif a.target.startswith(("http://", "https://")):
            tools, findings = from_github(a.target)
            target = a.target
        elif os.path.isdir(a.target):
            tools, findings = from_local(a.target)
            target = os.path.abspath(a.target)
        elif os.path.isfile(a.target):
            tools, findings = from_json_file(a.target)
            target = os.path.abspath(a.target)
        else:
            raise SystemExit(f"找不到: {a.target}")
    except urllib.error.URLError as e:
        print(f"取数失败: {e}", file=sys.stderr)
        return 2

    by_source: dict[str, list[dict]] = {}
    for t in tools:
        by_source.setdefault(t.get("_source", "tools/list"), []).append(t)
    for src, group in by_source.items():
        findings += S.scan_tools(group, src)

    if a.json:
        print(json.dumps({
            "target": target,
            "tools": len(tools),
            "findings": [f.as_dict() for f in S.sort_findings(findings)],
        }, ensure_ascii=False, indent=1))
    else:
        print(render(findings, target, len(tools), sys.stdout.isatty()))

    if a.fail_on != "never":
        threshold = S.SEV_ORDER[a.fail_on]
        if any(S.SEV_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
