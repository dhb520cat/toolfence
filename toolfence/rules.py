"""检测规则。

每条规则都来自一次真实的审计,不是想象出来的威胁:
  DESTRUCTIVE_NO_CONFIRM  — Mermail 用 prepare_destructive_action 换单次令牌,是正例
  PII_EXPOSURE            — T3N z-tenant-onboarding 的 PII guard
  HONEYPOT                — 2026 实测:73.2% 的 agent 赏金仓库钓 system prompt
  INJECTION_SURFACE       — 工具描述会原样进入 LLM 上下文
  UNBOUNDED_SCOPE         — 任意路径/URL/命令 = path traversal / SSRF / 命令注入
  CREDENTIAL_IN_PARAM     — 凭证走参数会进日志和对话历史
"""
from __future__ import annotations

import re

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"

# --- 破坏性动词。分两档:不可逆的和有副作用的 ---------------------------------
IRREVERSIBLE = (
    "delete", "remove", "destroy", "drop", "purge", "wipe", "erase",
    "revoke", "terminate", "kill",
)
OUTWARD = (
    "send", "publish", "transfer", "pay", "deploy", "execute", "shell", "invoke",
)
# 名词更常见的词。只有出现在动词位(名字的第一个 token)才算动作:
#   send_email / list_emails —— 前者是动作,后者 email 是宾语。
AMBIGUOUS_OUTWARD = ("post", "email", "tweet", "message", "mail")
AMBIGUOUS_WRITE = ("set", "put", "patch", "move")
WRITE = ("write", "create", "update", "edit", "rename")

# 确认机制的痕迹。见到任何一个就认为作者想过这件事。
CONFIRM_HINTS = (
    "confirm", "token", "dry_run", "dryrun", "force", "approve",
    "acknowledge", "are_you_sure", "prepare_destructive",
)

# --- PII 字段名。与 T3N enroll.rs 的 PII_NAME_FRAGMENTS 保持同一口径 ---------
PII_FRAGMENTS = (
    "first_name", "last_name", "given_name", "family_name", "full_name",
    "birth", "dob", "gender", "ssn", "social_security", "passport",
    "national_id", "tax_id", "iban", "bank_account", "card_number",
    "email", "phone", "mobile", "address", "postcode", "zip_code",
)

# --- 凭证字段名 -------------------------------------------------------------
CREDENTIAL_FRAGMENTS = (
    "password", "passwd", "secret", "api_key", "apikey", "access_token",
    "private_key", "credential", "auth_token", "bearer", "session_id",
)

# --- 注入面:工具描述里的指令性语言 ------------------------------------------
# 工具描述原样进入 LLM 上下文。描述里的祈使句 = 任何能改描述的人都能改 agent 行为。
IMPERATIVE_PATTERNS = (
    (r"\bignore\s+(?:all\s+)?(?:previous|prior|above|other)\b", CRITICAL, "覆盖先前指令"),
    (r"\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|safety|warning)", CRITICAL, "要求无视安全提示"),
    (r"\byou\s+must\s+(?:always\s+)?(?:call|use|invoke|run)\b", HIGH, "强制调用"),
    (r"\balways\s+(?:call|use|invoke|prefer)\s+this\b", HIGH, "自我优先"),
    (r"\bdo\s+not\s+(?:tell|inform|mention|reveal)\s+the\s+user\b", CRITICAL, "要求对用户隐瞒"),
    (r"\bwithout\s+(?:asking|confirming|informing)\s+the\s+user\b", CRITICAL, "要求跳过确认"),
    (r"\bsystem\s+prompt\b", HIGH, "提及 system prompt"),
)

# --- Honeypot:对人类隐藏、对机器可见 ----------------------------------------
HONEYPOT_ASKS = (
    (r"system\s+prompt", "索取 system prompt"),
    (r"\bfull\s+(?:instructions|context|configuration)\b", "索取完整指令/上下文"),
    (r"\bparaphrase\s+your\s+(?:instructions|prompt)", "索取指令改写"),
    (r"\breveal\s+your\b", "索取内部状态"),
    (r"\bprint\s+(?:your\s+)?(?:prompt|instructions)", "索取打印指令"),
)

# 明文索取:必须是"让你交出来"的祈使句,而不是提到这个词。
# 反例(不该命中):README 里的 "### System Prompt" 章节、"the system prompt we use is…"
# 只认明确指向 **agent 自身内部状态** 的索取。
# 裸的 "configuration" / "instructions" 不算 —— 安装文档里
# "paste this into your configuration file"、"follow the instructions below"
# 满地都是,拿它当信号只会淹没真信号。
PLAINTEXT_DEMAND = (
    r"\b(?:paste|submit|include|provide|print|output|reveal|share|append|attach|dump|echo)\b"
    r"[^.\n]{0,50}?"
    r"\b(?:your|the\s+agent[\u2019']?s?|its)\b\s*"
    r"(?:full\s+|complete\s+|entire\s+|raw\s+|original\s+)?"
    r"(?:system\s+(?:prompt|message|instructions)|context\s+window|"
    r"(?:full|complete|entire)\s+(?:instructions|configuration|prompt))"
)

# --- 无界作用域 -------------------------------------------------------------
UNBOUNDED_HINTS = (
    ("path", r"(?:any|arbitrary|absolute|full)\s+path", "任意路径 → path traversal"),
    ("url", r"(?:any|arbitrary)\s+url", "任意 URL → SSRF"),
    ("command", r"(?:any|arbitrary)\s+(?:command|shell)", "任意命令 → 命令注入"),
    ("query", r"(?:raw|arbitrary)\s+(?:sql|query)", "裸 SQL → 注入"),
)


# 已声明边界的表述。作者写了"只在允许的目录内",就不该再报作用域无界 ——
# 官方 filesystem server 的 search_files 正是如此。
BOUNDED_DECLARATIONS = (
    r"only\s+(?:works|searches|operates|reads|writes)\s+within",
    r"within\s+(?:the\s+)?allowed\s+(?:director|path)",
    r"restricted\s+to\s+",
    r"must\s+be\s+(?:within|under)\s+",
    r"\bsandbox(?:ed)?\b",
    r"allowed\s+directories",
)


def declares_boundary(text: str) -> bool:
    return any(re.search(p, text, re.I) for p in BOUNDED_DECLARATIONS)


# 明确的只读动词。出现在**动词位(第一个 token)**时,整个工具就是读操作 ——
# `get_create_fields` 是"取创建时可用的字段",主动作是 get,create 只是宾语修饰。
READ_VERBS = (
    "get", "list", "read", "search", "find", "fetch", "query",
    "describe", "show", "check", "count", "view", "inspect", "lookup",
)


def classify_destructive(name: str) -> tuple[str, str] | None:
    """返回 (档位, 命中的动词)。

    动词可以出现在任意 token 位置(`git_commit`、`delete_file` 都要能认),
    但**名词歧义的词只认动词位**——否则 `list_emails` 会被当成"发邮件"。
    """
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)      # camelCase → snake
    tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", snake.lower()) if t]
    if not tokens:
        return None
    head = tokens[0]
    rest = set(tokens)

    # 动词位是只读动词 → 整个工具是读操作,后面的词是宾语不是动作。
    if head in READ_VERBS:
        return None

    for verb in IRREVERSIBLE:
        if verb in rest:
            return ("irreversible", verb)
    for verb in OUTWARD:
        if verb in rest:
            return ("outward", verb)
    for verb in AMBIGUOUS_OUTWARD:
        if head == verb:
            return ("outward", verb)
    for verb in WRITE:
        if verb in rest:
            return ("write", verb)
    for verb in AMBIGUOUS_WRITE:
        if head == verb:
            return ("write", verb)
    return None


def has_confirm_affordance(tool: dict) -> str | None:
    """工具自身是否提供了确认手段。返回命中的证据,没有则 None。"""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    for pname in props:
        low = pname.lower()
        for hint in CONFIRM_HINTS:
            if hint in low:
                return f"参数 {pname}"
    desc = (tool.get("description") or "").lower()
    for hint in ("confirmation token", "prepare_destructive", "dry run", "dry-run"):
        if hint in desc:
            return f"描述提及 {hint}"
    return None
