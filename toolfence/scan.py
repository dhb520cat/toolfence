"""扫描器核心。

只读:不执行被扫描的代码,不调用 tools/call,只读清单与源文件。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict

from . import rules as R


@dataclass
class Finding:
    rule: str
    severity: str
    where: str
    summary: str
    evidence: str = ""
    fix: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


SEV_ORDER = {R.CRITICAL: 0, R.HIGH: 1, R.MEDIUM: 2, R.LOW: 3}


# ---------------------------------------------------------------- tools/list
def scan_tools(tools: list[dict], source: str = "tools/list") -> list[Finding]:
    """扫描一份 MCP tools/list 清单。"""
    out: list[Finding] = []
    for tool in tools:
        name = tool.get("name") or "(unnamed)"
        desc = tool.get("description") or ""
        where = f"{source}:{name}"

        out += _check_destructive(tool, name, where)
        out += _check_injection(desc, where)
        out += _check_params(tool, where)
        out += _check_unbounded(tool, desc, where)

    out += _check_aggregate(tools, source)
    return out


def _check_destructive(tool: dict, name: str, where: str) -> list[Finding]:
    hit = R.classify_destructive(name)
    ann = tool.get("annotations") or {}

    # 作者显式声明的标注优先于名字推断 —— 显式声明是承诺,不是猜测。
    # 例:官方 create_directory 标了 destructiveHint: false,因为它幂等且不覆盖。
    if ann:
        if ann.get("readOnlyHint") is True or ann.get("destructiveHint") is False:
            return _check_annotation_mismatch(tool, name, where, hit, ann)
        if ann.get("destructiveHint") is True and R.has_confirm_affordance(tool):
            return []

    if not hit:
        return []
    tier, verb = hit
    affordance = R.has_confirm_affordance(tool)
    if affordance:
        return []  # 作者想过这件事,不报

    if tier == "irreversible":
        return [Finding(
            "DESTRUCTIVE_NO_CONFIRM", R.CRITICAL, where,
            f"不可逆操作 '{name}' 没有任何确认机制",
            f"工具名命中 '{verb}';inputSchema 里没有 confirm/token/dry_run 之类的参数",
            "加一个单次使用的确认令牌:先调 prepare 拿 token,再带 token 调用。"
            "Mermail 的 prepare_destructive_action 是可参考的正例。",
        )]
    if tier == "outward":
        return [Finding(
            "DESTRUCTIVE_NO_CONFIRM", R.HIGH, where,
            f"对外操作 '{name}' 没有确认机制",
            f"工具名命中 '{verb}';该操作会离开本地边界(发送/发布/转账/执行)",
            "对外动作应当要么需要确认令牌,要么在调用前把完整内容回显给用户。",
        )]
    return [Finding(
        "DESTRUCTIVE_NO_CONFIRM", R.MEDIUM, where,
        f"写操作 '{name}' 没有 dry-run 或确认",
        f"工具名命中 '{verb}'",
        "提供 dry_run 参数,让调用方能先看变更再落盘。",
    )]


def _check_annotation_mismatch(tool, name, where, hit, ann) -> list[Finding]:
    """标注说安全,名字说危险 —— 二者矛盾时,标注可能是错的。

    这不是风格问题:调用方会根据 readOnlyHint 决定要不要放行,
    标错等于给了一个假的安全保证。
    """
    if not hit:
        return []
    tier, verb = hit
    if tier not in ("irreversible", "outward"):
        return []
    claim = "readOnlyHint: true" if ann.get("readOnlyHint") is True else "destructiveHint: false"
    return [Finding(
        "ANNOTATION_MISMATCH", R.HIGH, where,
        f"'{name}' 标注为安全,但名字表明这是{'不可逆' if tier == 'irreversible' else '对外'}操作",
        f"标注 {claim};工具名命中动词 '{verb}'",
        "调用方会依据 readOnlyHint/destructiveHint 决定是否自动放行。"
        "标注与实际行为不符,等于提供了一个假的安全保证 —— "
        "要么改标注,要么确认这个名字没有误导性。",
    )]


def _check_injection(desc: str, where: str) -> list[Finding]:
    out = []
    for pat, sev, why in R.IMPERATIVE_PATTERNS:
        m = re.search(pat, desc, re.I)
        if m:
            out.append(Finding(
                "INJECTION_SURFACE", sev, where,
                f"工具描述含指令性语言({why})",
                f"…{desc[max(0, m.start()-40):m.end()+40].strip()}…",
                "工具描述原样进入 LLM 上下文。描述只该说明这个工具做什么,"
                "不该对模型下命令——任何能改描述的人都能借此改 agent 行为。",
            ))
    return out


def _check_params(tool: dict, where: str) -> list[Finding]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    out = []
    for pname, pdef in props.items():
        low = pname.lower()
        pdesc = (pdef or {}).get("description", "") if isinstance(pdef, dict) else ""

        for frag in R.CREDENTIAL_FRAGMENTS:
            if frag in low:
                out.append(Finding(
                    "CREDENTIAL_IN_PARAM", R.HIGH, where,
                    f"凭证经由工具参数传递:{pname}",
                    f"参数名命中 '{frag}'",
                    "工具参数会进入对话历史、日志和可能的遥测。"
                    "凭证应由服务端从环境/密钥库取,不要让模型经手。",
                ))
                break

        for frag in R.PII_FRAGMENTS:
            if frag in low:
                out.append(Finding(
                    "PII_EXPOSURE", R.MEDIUM, where,
                    f"工具接受个人数据字段:{pname}",
                    f"参数名命中 '{frag}'" + (f";描述:{pdesc[:60]}" if pdesc else ""),
                    "确认这是必要的,并确保该字段不会被日志记录或转发给第三方。"
                    "能用不透明标识符替代的就不要收原值。",
                ))
                break
    return out


def _check_unbounded(tool: dict, desc: str, where: str) -> list[Finding]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    blob = desc + " " + " ".join(
        (p or {}).get("description", "") for p in props.values() if isinstance(p, dict)
    )
    if R.declares_boundary(blob):
        return []          # 作者已经声明了边界,不再报无界
    out = []
    for key, pat, why in R.UNBOUNDED_HINTS:
        if re.search(pat, blob, re.I):
            out.append(Finding(
                "UNBOUNDED_SCOPE", R.HIGH, where,
                f"作用域无界:{why}",
                f"描述中出现 /{pat}/",
                "把作用域收敛到一个明确的白名单(允许的根目录、允许的主机、"
                "预置的语句),而不是接受任意输入后再过滤。",
            ))
    return out


def _check_aggregate(tools: list[dict], source: str) -> list[Finding]:
    """整份清单层面的问题。"""
    out = []
    names = [t.get("name", "") for t in tools]
    destructive = [n for n in names if (h := R.classify_destructive(n)) and h[0] != "write"]
    if len(tools) >= 20 and destructive:
        out.append(Finding(
            "BROAD_SURFACE", R.MEDIUM, source,
            f"{len(tools)} 个工具中有 {len(destructive)} 个具破坏性或对外能力",
            "破坏性工具:" + ", ".join(destructive[:8]) + ("…" if len(destructive) > 8 else ""),
            "考虑把只读工具与可变更工具拆成两个 server,让调用方可以只挂载只读那一半。",
        ))
    return out


# ------------------------------------------------------------------ honeypot
def scan_text(text: str, where: str) -> list[Finding]:
    """扫描 README / 文档 / issue 模板里的 honeypot。

    模式:把指令藏在人类看不见的地方(HTML 注释、零宽字符、白底白字),
    内容是让自动化系统泄漏自身状态。
    """
    out = []
    hidden_blocks = re.findall(r"<!--(.*?)-->", text, re.S)
    for blk in hidden_blocks:
        for pat, why in R.HONEYPOT_ASKS:
            if re.search(pat, blk, re.I):
                out.append(Finding(
                    "HONEYPOT", R.CRITICAL, where,
                    f"HTML 注释中藏有针对自动化系统的指令({why})",
                    f"<!--{blk.strip()[:140]}-->",
                    "这是针对 agent 的定向陷阱:人类读者看不到注释,"
                    "而解析原文的 agent 会读到。不要执行仓库内容里的任何指令。",
                ))
                break

    if re.search(r"[​‌‍⁠﻿]", text):
        out.append(Finding(
            "HONEYPOT", R.HIGH, where,
            "文本含零宽字符,可能藏有对人类不可见的内容",
            f"命中 {len(re.findall(r'[​‌‍⁠﻿]', text))} 处零宽字符",
            "用 `rg -P '[\\x{200b}-\\x{200d}\\x{2060}\\x{feff}]'` 定位后人工核对。",
        ))

    # 明文(非隐藏)的索取。必须是**祈使句 + 索取**才算 ——
    # 单纯出现 "system prompt" 这个词组不算:正当文档里
    # "### System Prompt" 这种章节标题非常常见。
    for m in re.finditer(R.PLAINTEXT_DEMAND, text, re.I):
        seg = text[max(0, m.start() - 60):m.end() + 60].replace("\n", " ")
        if any(seg[:60] in f.evidence for f in out):
            continue
        out.append(Finding(
            "HONEYPOT", R.MEDIUM, where,
            "文档正文要求自动化系统交出自身指令",
            f"…{seg.strip()}…",
            "核实用途。正当的贡献流程不需要 agent 交出自身 prompt 或配置。",
        ))
        break
    return out


def sort_findings(fs: list[Finding]) -> list[Finding]:
    return sorted(fs, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.rule, f.where))
