"""从源码里提取工具定义。

真实的 MCP server 把工具定义在代码里,不是 JSON 清单里。支持三种主流写法:
  TS   server.registerTool("name", { description, inputSchema, annotations }, handler)
  TS   { name: "...", description: "...", inputSchema: {...} }   (数组风格)
  Py   @mcp.tool() / types.Tool(name=..., description=...)

只做词法级提取,不执行任何代码。提不准就不提 —— 宁可漏,不可错报。
"""
from __future__ import annotations

import re

# ── TS: server.registerTool("name", { ... }, handler) ────────────────────────
TS_REGISTER = re.compile(
    r"""registerTool\s*\(\s*["'`](?P<name>[\w.\-]+)["'`]\s*,\s*\{""", re.S)

# ── TS: { name: "x", description: "y" } ──────────────────────────────────────
TS_OBJECT = re.compile(
    r"""\{\s*name\s*:\s*["'`](?P<name>[\w.\-]+)["'`]\s*,""", re.S)

# ── Py: @mcp.tool(...) def fn(...)  /  types.Tool(name="x", description="y") ──
PY_DECORATOR = re.compile(
    r"""@\w+\.tool\([^)]*\)\s*(?:async\s+)?def\s+(?P<name>\w+)""", re.S)
PY_TYPES_TOOL = re.compile(
    r"""Tool\(\s*name\s*=\s*["'](?P<name>[\w.\-]+)["']""", re.S)


def _balanced(text: str, start: int, open_ch="{", close_ch="}") -> str:
    """从 start(指向 open_ch)取出配对的块。字符串内的括号不计。"""
    depth = 0
    i = start
    quote = None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return text[start:start + 4000]


def _js_string_after(block: str, key: str) -> str:
    """取 `key:` 后面的字符串,处理 "a" + "b" 的拼接和模板串。"""
    m = re.search(rf"""\b{key}\s*:\s*""", block)
    if not m:
        return ""
    rest = block[m.end():]
    parts, i = [], 0
    while i < len(rest):
        ch = rest[i]
        if ch in " \t\r\n+":
            i += 1
            continue
        if ch in "\"'`":
            q = ch
            i += 1
            buf = []
            while i < len(rest):
                c = rest[i]
                if c == "\\" and i + 1 < len(rest):
                    buf.append(rest[i + 1]); i += 2; continue
                if c == q:
                    i += 1; break
                buf.append(c); i += 1
            parts.append("".join(buf))
            continue
        break
    return " ".join(parts).strip()


def _js_annotations(block: str) -> dict:
    m = re.search(r"\bannotations\s*:\s*\{", block)
    if not m:
        return {}
    blk = _balanced(block, block.index("{", m.end() - 1))
    out = {}
    for k, v in re.findall(r"(\w+)\s*:\s*(true|false)", blk):
        out[k] = (v == "true")
    return out


def _js_param_names(block: str) -> list[str]:
    m = re.search(r"\binputSchema\s*:\s*", block)
    if not m:
        return []
    rest = block[m.end():]
    if rest.lstrip().startswith("{"):
        blk = _balanced(rest, rest.index("{"))
        # 顶层的 key: 视为参数名(zod 或 JSON Schema 的 properties 都近似适用)
        inner = re.search(r"\bproperties\s*:\s*\{", blk)
        if inner:
            blk = _balanced(blk, blk.index("{", inner.end() - 1))
        return re.findall(r"[\{,]\s*[\"']?(\w+)[\"']?\s*:", blk)
    # inputSchema: SomeZodSchema.shape —— 拿不到字段名,如实返回空
    return []


def from_source(text: str, rel: str) -> list[dict]:
    """返回 tools/list 形状的 dict 列表。"""
    tools: list[dict] = []
    seen: set[str] = set()

    def add(name: str, desc: str = "", params: list[str] | None = None,
            ann: dict | None = None):
        if not name or name in seen:
            return
        seen.add(name)
        t = {"name": name, "description": desc, "_source": rel}
        if params:
            t["inputSchema"] = {"type": "object",
                                "properties": {p: {} for p in params}}
        if ann:
            t["annotations"] = ann
        tools.append(t)

    if rel.endswith((".ts", ".js", ".tsx", ".mjs")):
        for m in TS_REGISTER.finditer(text):
            blk = _balanced(text, text.index("{", m.end() - 1))
            add(m.group("name"), _js_string_after(blk, "description"),
                _js_param_names(blk), _js_annotations(blk))
        for m in TS_OBJECT.finditer(text):
            blk = _balanced(text, m.start())
            if "description" not in blk:
                continue
            add(m.group("name"), _js_string_after(blk, "description"),
                _js_param_names(blk), _js_annotations(blk))

    elif rel.endswith(".py"):
        for m in PY_DECORATOR.finditer(text):
            tail = text[m.end():m.end() + 900]
            doc = re.search(r'"""(.*?)"""', tail, re.S)
            add(m.group("name"), (doc.group(1).strip() if doc else ""))
        for m in PY_TYPES_TOOL.finditer(text):
            blk = text[m.start():m.start() + 1200]
            d = re.search(r'description\s*=\s*(?:\(\s*)?["\']{1,3}(.*?)["\']{1,3}', blk, re.S)
            add(m.group("name"), (d.group(1).strip() if d else ""))

    return tools
