"""从源码里提取工具定义。

真实的 MCP server 把工具定义在代码里,不是 JSON 清单里。支持三种主流写法:
  TS   server.registerTool("name", { description, inputSchema, annotations }, handler)
  TS   { name: "...", description: "...", inputSchema: {...} }   (数组风格)
  Py   @mcp.tool() / types.Tool(name=..., description=...)
  Py   TOOLS = [{"name": ..., "description": ..., "inputSchema": {...}}]
  Go   mcp.Tool{ Name: "...", Description: ..., Annotations: &mcp.ToolAnnotations{...} }

只做词法级提取,不执行任何代码。提不准就不提 —— 宁可漏,不可错报。
"""
from __future__ import annotations

import ast
import re
import warnings

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

# ── Go: mcp.Tool{ Name: "x", Description: ..., Annotations: &mcp.ToolAnnotations{} } ──
GO_TOOL = re.compile(
    r"""Tool\{\s*(?:[^{}]*?\s)?Name\s*:\s*"(?P<name>[\w.\-]+)"\s*,""", re.S)

# Go 的 annotation 字段是 PascalCase,MCP 规范是 camelCase。
GO_ANN_MAP = {
    "ReadOnlyHint": "readOnlyHint", "DestructiveHint": "destructiveHint",
    "IdempotentHint": "idempotentHint", "OpenWorldHint": "openWorldHint",
}


def _go_string_after(block: str, key: str) -> str:
    """取 `Key:` 后的字符串。描述常包在 i18n 包装里:t("KEY", "真正的文本")
    —— 这时要第二个参数,第一个只是翻译键。"""
    m = re.search(rf"""\b{key}\s*:\s*""", block)
    if not m:
        return ""
    rest = block[m.end():].lstrip()
    if rest.startswith(("`", '"')):
        q = rest[0]
        end = rest.index(q, 1) if q == "`" else _end_of_go_str(rest)
        return rest[1:end]
    # t("KEY", "text") / translate("KEY", "text")
    call = re.match(r"""\w+\(\s*"[^"]*"\s*,\s*""", rest)
    if call:
        tail = rest[call.end():]
        if tail.startswith(('"', "`")):
            q = tail[0]
            end = tail.index(q, 1) if q == "`" else _end_of_go_str(tail)
            return tail[1:end]
    return ""


def _end_of_go_str(s: str) -> int:
    i = 1
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            return i
        i += 1
    return len(s) - 1


def _go_annotations(block: str) -> dict:
    m = re.search(r"Annotations\s*:\s*&?\w*\.?ToolAnnotations\{", block)
    if not m:
        return {}
    blk = _balanced(block, block.index("{", m.end() - 1))
    out = {}
    for k, v in re.findall(r"(\w+)\s*:\s*(true|false)", blk):
        if k in GO_ANN_MAP:
            out[GO_ANN_MAP[k]] = (v == "true")
    return out


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


def _py_params(tail: str) -> list[str]:
    """从函数签名取参数名。

    形参常带 Field(...) 默认值和跨行的类型标注,所以取配对的 (...) 再扫
    顶层的 `name:` / `name=` —— 嵌套括号里的不算。
    """
    if not tail.startswith("("):
        i = tail.find("(")
        if i < 0 or i > 4:
            return []
        tail = tail[i:]
    sig = _balanced(tail, 0, "(", ")")
    names, depth, buf = [], 0, ""
    for ch in sig[1:-1]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and ch == ",":
            names.append(buf); buf = ""
        else:
            buf += ch
    names.append(buf)
    out = []
    for n in names:
        n = n.strip()
        if not n or n.startswith(("*", "#")):
            continue
        head = re.match(r"(\w+)\s*[:=]", n) or re.fullmatch(r"(\w+)", n)
        if head and head.group(1) not in ("self", "cls", "ctx", "context"):
            out.append(head.group(1))
    return out


def _py_docstring(tail: str) -> str:
    m = re.search(r'"""(.*?)"""', tail[:4000], re.S)
    return m.group(1).strip() if m else ""


def _py_dict_literals(text: str) -> list[dict]:
    """认出 Python 里以字典字面量声明的工具清单。

    手写 JSON-RPC 的 server 常这样写:
        TOOLS = [{"name": "x", "description": "y", "inputSchema": {...}}]

    用 ast **解析**,从不 eval —— 这个工具的全部意义就是不执行它读的东西。
    只接受纯字面量;含变量或函数调用的字典跳过,宁可漏也不猜。
    """
    # ast.parse 对畸形源码会发 SyntaxWarning(无效转义之类),
    # 那会直接打到用户终端,把一份报告弄脏。扫描器解析别人的代码,
    # 别人代码里的噪音不该变成我们的输出。
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []

    out: list[dict] = []

    def literal(node):
        try:
            return ast.literal_eval(node)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return None

    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        for el in node.elts:
            if not isinstance(el, ast.Dict):
                continue
            keys = [k.value for k in el.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            if "name" not in keys:
                continue
            if not ({"description", "inputSchema", "input_schema"} & set(keys)):
                continue
            d = literal(el)
            if not isinstance(d, dict) or not isinstance(d.get("name"), str):
                continue
            out.append(d)
    return out


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

    elif rel.endswith(".go"):
        for m in GO_TOOL.finditer(text):
            blk = _balanced(text, text.rindex("{", 0, m.end()))
            add(m.group("name"), _go_string_after(blk, "Description"),
                None, _go_annotations(blk))

    elif rel.endswith(".py"):
        for m in PY_DECORATOR.finditer(text):
            tail = text[m.end():]
            add(m.group("name"), _py_docstring(tail), _py_params(tail))
        for d in _py_dict_literals(text):
            schema = d.get("inputSchema") or d.get("input_schema") or {}
            props = list((schema.get("properties") or {})) if isinstance(schema, dict) else []
            add(d["name"], d.get("description", "") or "", props, d.get("annotations"))
        for m in PY_TYPES_TOOL.finditer(text):
            blk = text[m.start():m.start() + 1200]
            d = re.search(r'description\s*=\s*(?:\(\s*)?["\']{1,3}(.*?)["\']{1,3}', blk, re.S)
            add(m.group("name"), (d.group(1).strip() if d else ""))

    return tools
