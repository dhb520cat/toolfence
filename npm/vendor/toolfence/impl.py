"""实现层检查:工具**怎么做**,而不是它**声称**做什么。

声明层的问题(没有确认、标注撒谎)是设计选择,通常不可利用。
实现层的问题是真漏洞:模型可控的字符串流进 shell、路径拼接或 URL 抓取。

依然只做词法分析,不执行任何被扫描的代码。
"""
from __future__ import annotations

import re

from .scan import Finding
from . import rules as R

# 模型可控的输入 —— MCP 工具的参数就是模型写的字符串。
# 认出「这个变量来自工具参数」的常见写法。
ARG_SOURCES = (
    r"\bargs\s*[\.\[]", r"\bargs\b", r"\bparams\s*[\.\[]", r"\barguments\s*[\.\[]",
    r"\brequest\.params", r"\binput\s*[\.\[]", r"\bpayload\s*[\.\[]",
)

# ── 命令注入 ────────────────────────────────────────────────────────────────
# exec/system/shell=True 接到模板串或拼接串。
SHELL_SINKS = [
    # JS/TS: child_process.exec(`...${x}...`) —— exec 走 shell,execFile 不走
    (r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`\"'][^`\"']*\$\{",
     "js-template", "exec() 把整串交给 shell,模板插值即注入点"),
    (r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[\w.]+\s*\+",
     "js-concat", "exec() 参数由字符串拼接构成"),
    # Python: os.system / subprocess(..., shell=True)
    (r"\bos\.system\s*\(\s*f?[\"']",
     "py-system", "os.system 总是经过 shell"),
    (r"shell\s*=\s*True",
     "py-shell-true", "subprocess(shell=True) 把参数交给 shell 解析"),
    (r"\bos\.popen\s*\(",
     "py-popen", "os.popen 经过 shell"),
    # Go: exec.Command("sh", "-c", ...)
    (r"exec\.Command\s*\(\s*[\"'](?:sh|bash|zsh|cmd)[\"']\s*,\s*[\"']-c[\"']",
     "go-sh-c", "exec.Command 显式走 sh -c"),
]

# ── 路径穿越 ────────────────────────────────────────────────────────────────
PATH_SINKS = [
    (r"\bpath\.join\s*\([^)]*\b(?:args|params|input|arguments)\b",
     "js-join", "path.join 接到工具参数;join 不阻止 ../"),
    (r"\bos\.path\.join\s*\([^)]*\b(?:args|params|arguments)\b",
     "py-join", "os.path.join 接到工具参数;绝对路径参数会直接覆盖前缀"),
    (r"\b(?:readFile|writeFile|unlink|rm|rmdir|createReadStream)(?:Sync)?\s*\(\s*(?:args|params|input)\b",
     "js-fs-direct", "fs 操作直接使用工具参数"),
    (r"\bopen\s*\(\s*(?:args|params|arguments)\b",
     "py-open-direct", "open() 直接使用工具参数"),
]

# ── SSRF ────────────────────────────────────────────────────────────────────
URL_SINKS = [
    (r"\bfetch\s*\(\s*(?:args|params|input|arguments)\b",
     "js-fetch", "fetch 直接使用工具提供的 URL"),
    # `request` 是极常见的普通函数名 —— cloudflare/mcp-server-cloudflare 里
    # request(params.gateway_id, params.log_id, …) 是内部调用,不是 HTTP。
    # 只认带 HTTP 方法的形式,或参数名本身就是 url。
    (r"\b(?:axios|got)\s*(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(\s*(?:args|params|input)\b",
     "js-http", "HTTP 客户端直接使用工具提供的 URL"),
    (r"\b(?:axios|got|fetch|request)\s*(?:\.\w+)?\s*\(\s*[\w.]*\b(?:args|params|input|arguments)\b[\w.]*\.(?:url|uri|endpoint|href)\b",
     "js-http-url", "HTTP 客户端直接使用工具提供的 URL"),
    (r"\brequests\.(?:get|post|put|delete|head)\s*\(\s*(?:args|params|arguments)\b",
     "py-requests", "requests 直接使用工具提供的 URL"),
    (r"\burllib\.request\.urlopen\s*\(\s*(?:args|params)\b",
     "py-urlopen", "urlopen 直接使用工具提供的 URL"),
]

# 出现这些说明作者做了校验,降级或不报。
GUARDS = (
    r"\bresolve\w*\s*\(", r"\bnormali[sz]e\s*\(", r"\bstartsWith\s*\(",
    r"\bis_?within\b", r"\ballowed\w*\b", r"\bwhitelist\b", r"\ballowlist\b",
    r"\bvalidate\w*\s*\(", r"\bsanitiz\w*\s*\(", r"\bescape\w*\s*\(",
    r"\bshlex\.quote\b", r"\bshell[Ee]scape\b", r"\brealpath\b",
    r"\bcommonpath\b", r"\bcommonprefix\b",
)


def _guarded_near(text: str, pos: int, window: int = 700) -> str | None:
    """命中点附近有没有校验痕迹。有就说明作者想过这件事。"""
    seg = text[max(0, pos - window): pos + window]
    for g in GUARDS:
        m = re.search(g, seg)
        if m:
            return m.group(0)
    return None


def _model_controlled(text: str, pos: int, window: int = 400) -> bool:
    seg = text[max(0, pos - window): pos + window]
    return any(re.search(p, seg) for p in ARG_SOURCES)


# 一条危险模式出现在**注释、文档字符串或数据表**里时,那不是代码路径。
# 安全工具的规则表长得就像它要找的东西 —— toolfence 扫自己时,
# SHELL_SINKS 里的模式和它们的中文描述都曾被这些规则自己报成命令注入。
_COMMENT = re.compile(r"^\s*(?:#|//|\*|/\*)")
# 文档字符串常举反例:"Never call exec.Command(...) here."
_DOCSTRING_LINE = re.compile(r'^\s*(?:"""|\'\'\'|r"""|r\'\'\')')
# 数据行:`(r"...", "kind", "描述"),` 这种形状 —— 开头是括号/引号,结尾是逗号。
_DATA_ROW = re.compile(r"""^\s*[\(\["']""")
_ROW_END = re.compile(r"""[,\)\]]\s*$""")
# 真正的语句特征:赋值、return、控制流、独立调用。
_STATEMENT = re.compile(
    r"""^\s*(?:return|await|yield|if|elif|while|for|with|assert|raise|"""
    r"""const |let |var |func |def |[\w.\[\]]+\s*=(?!=))""")


def _not_executable(text: str, pos: int) -> bool:
    """命中点所在行是注释、或是数据表里的一行,而不是会被执行的语句。"""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)]
    if _COMMENT.search(line) or _DOCSTRING_LINE.search(line):
        return True
    if _STATEMENT.search(line):
        return False          # 看起来是真语句,按代码处理
    return bool(_DATA_ROW.search(line) and _ROW_END.search(line))


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_impl(text: str, rel: str) -> list[Finding]:
    """扫实现代码。只在「模型可控输入 → 危险汇点」且附近无校验时报告。"""
    out: list[Finding] = []
    checks = [
        ("COMMAND_INJECTION", SHELL_SINKS, R.CRITICAL,
         "把工具参数交给 shell 解释。用 execFile/subprocess 的数组形式,"
         "或 shlex.quote;不要拼接命令行。"),
        ("PATH_TRAVERSAL", PATH_SINKS, R.HIGH,
         "把参数 realpath 之后,断言它仍在允许的根目录内再使用 —— "
         "path.join 不会阻止 ../,绝对路径参数还会直接覆盖前缀。"),
        ("SSRF", URL_SINKS, R.HIGH,
         "对目标主机做白名单,并拒绝回环、链路本地与私有网段;"
         "云环境里 169.254.169.254 是元数据服务。"),
    ]
    for rule, sinks, sev, fix in checks:
        for pat, kind, why in sinks:
            for m in re.finditer(pat, text):
                if not _model_controlled(text, m.start()):
                    continue
                if _not_executable(text, m.start()):
                    continue
                guard = _guarded_near(text, m.start())
                line = _line_of(text, m.start())
                snippet = text[m.start():m.start() + 110].split("\n")[0].strip()
                if guard:
                    out.append(Finding(
                        rule, R.LOW, f"{rel}:{line}",
                        f"{why}(附近有校验:{guard})",
                        snippet,
                        "看起来已有防护。确认该校验确实覆盖这条路径,而不是同一文件里的别处。",
                    ))
                else:
                    out.append(Finding(
                        rule, sev, f"{rel}:{line}",
                        why,
                        snippet,
                        fix,
                    ))
    return out
