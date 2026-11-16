# Standard-library Python 3, tested with 3.14 on Windows 11 (uses orjson when it is installed).
# MIT License: see LICENSE-CODE in the repository root.
"""Which sites did an AI agent fail to open, and with which tool? (Page2AI T262, 2026-11-16)

Sources (all local, read-only):
  1. Claude Code transcripts  ~/.claude/projects/**/*.jsonl  (CLI = entrypoint "cli", Claude Desktop's Code tab =
     "claude-desktop", headless/SDK runs = "sdk-cli"; sub-agent transcripts under <session>/subagents/).
  2. Claude Desktop MCP logs  <Desktop data>/logs/mcp-server-*.log (+ mcp*.log for servers without their own file):
     the JSON-RPC traffic of LOCAL MCP servers. Calls that also sit in a transcript are flagged as twins, the rest
     are Desktop chat (or Cowork).
  3. --claude-export <conversations.json|zip>: claude.ai account export (chat history incl. Desktop chat).
     EXPERIMENTAL: generic walker, schema not verified on a real export.

Output (private, local): <out>/attempts.jsonl, hosts.csv, report.md. No query strings, no fragments, no raw
results; tokens/emails masked in error details; localhost/private hosts dropped unless --include-local.
Usage: python fetch_failures.py [--out DIR] [--since YYYY-MM-DD] [--include-local] [--claude-export PATH]
       python fetch_failures.py --selftest
"""
import argparse
import bisect
import collections
import csv
import glob
import ipaddress
import json
import os
import re
import sys
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import urlsplit

try:
    import orjson
    loads = orjson.loads
except ImportError:  # pragma: no cover
    loads = json.loads

HOME = os.path.expanduser("~")
CC_ROOT = os.path.join(HOME, ".claude", "projects")
DESKTOP_ROOTS = [os.path.expandvars(r"%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude"),
                 os.path.expandvars(r"%APPDATA%\Claude")]
DESKTOP_ROOTS += glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude"))
URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]{}\\`|,;]+", re.I)
URL_KEYS = ("url", "urls", "uri", "href", "link", "links", "target_url", "page_url", "start_url")
NAV_TOOL = re.compile(r"(navigate|read_url|fetch|scrape|crawl|extract|make_request|bulk_get|^get$|new_page|"
                      r"page_to_markdown|web_fetch|map$|open$)", re.I)
FETCH_VERB = re.compile(r"\b(curl(\.exe)?|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", re.I)
SKIP_TOOLS = {"Agent", "Task", "WebSearch", "TodoWrite", "Write", "Edit", "Read", "Grep", "Glob", "TaskCreate",
              "TaskUpdate", "SendMessage", "Artifact", "AskUserQuestion", "Monitor", "SubagentHandback",
              "RemoteTrigger", "SendUserFile", "NotebookEdit"}

# --- classification ---------------------------------------------------------------------------------------------
SITE = {"blocked", "challenge", "js_wall", "login_wall", "network", "server_error", "not_found", "paywall",
        "tool_policy"}
STRONG = ["cf-chl", "challenge-platform", "/cdn-cgi/challenge", "captcha-delivery", "px-captcha",
          "enable javascript and cookies to continue", "checking your browser", "checking if the site connection",
          "verify you are human", "verifying you are human", "please verify you are a human",
          "why have i been blocked", "sorry, you have been blocked", "pardon our interruption",
          "unusual traffic from your computer", "ddos protection by", "please complete the security check",
          "requiring captcha"]
HEAD_PHRASES = ["cloudflare challenge", "challenge page", "bot protection", "bot-protection", "anti-bot",
                "security challenge", "blocked by cloudflare", "captcha page"]
WEAK_HEAD = ["just a moment", "access denied", "request blocked", "are you a robot", "robot or human",
             "attention required"]
JS_WALL = ["enable javascript", "requires javascript", "javascript is required", "javascript to run this app",
           "javascript is disabled", "turn on javascript"]
LOGIN = ["sign in to continue", "log in to continue", "please log in", "please sign in", "login required",
         "you must be logged in", "authentication required", "sign in to view", "log in to view"]
NET = [("enotfound", "dns"), ("eai_again", "dns"), ("err_name_not_resolved", "dns"),
       ("could not be resolved", "dns"), ("getaddrinfo", "dns"), ("econnrefused", "refused"),
       ("err_connection_refused", "refused"), ("unable to connect", "refused"), ("econnreset", "reset"),
       ("socket hang up", "reset"), ("err_connection_reset", "reset"), ("err_connection_closed", "reset"),
       ("timeout", "timeout"), ("timed out", "timeout"), ("etimedout", "timeout"), ("err_timed_out", "timeout"),
       ("certificate", "tls"), ("ssl", "tls"), ("err_cert", "tls"), ("too many redirects", "redirects"),
       ("err_too_many_redirects", "redirects"), ("maxcontentlength", "too_large"), ("err_aborted", "aborted"),
       ("net::err_", "net"), ("err_http2", "net"), ("err_empty_response", "net")]
TOOL_ENV = ["no such tool available", "insufficient credits", "executable doesn't exist", "already in use",
            "mcp-remote", "not connected", "transport closed", "connection closed", "api error",
            "output token maximum", "credits", "rate limit exceeded for your",
            "target page, context or browser has been closed", "browser has been closed", "tab not found",
            "no tab", "cdp sendcommand", "renderer may be frozen", "extension is not connected",
            "browser extension", "not available in this context", "playwright install",
            "inspected target navigated or closed", "unknown tool", "unable to verify if domain"]
NET_FIRST = ["net::err_", "enotfound", "eai_again", "econnrefused", "econnreset", "etimedout", "certificate",
             "too many redirects", "maxcontentlength", "socket hang up", "all scraping engines failed",
             "socket connection was closed", "typo in the url or port"]
PERM = ["haven't granted", "permission", "denied by", "user doesn't want", "user rejected", "auto mode",
        "hook error", "blocked by", "requires approval", "not allowed by your", "secrets_guard",
        "path is protected", "<tool_use_error>blocked:"]
USAGE = ["input validation error", "invalid arguments", "invalid_string", "invalid url", "invalid_url",
         "is not a valid url", "must be a valid url", "unsupported protocol", "validation error for call"]
POLICY = ["claude code is unable to fetch from", "url_not_allowed", "not allowed to fetch",
          "blocked domain", "domain is blocked"]
# T266 (panel T263): a fetch SERVICE refusing a site (Firecrawl «we do not support this site») is not Claude Code's list,
# and a robots.txt refusal is the site's rule honoured by the tool; Anthropic's `url_not_accessible` is an HTTP failure.
SERVICE_POLICY = ["do not support this site", "we do not support"]
ROBOTS = ["robots.txt", "disallowed by robots"]
SITE_DENY = ["blocked by cloudflare", "sorry, you have been blocked", "attention required! | cloudflare",
             "you don't have permission to access"]
COUNTER_RE = re.compile(r"(?i)(just a moment|cf-chl|captcha|access denied|cloudflare)\W{0,3}[:=]\s*\d+")
SNIP_RE = re.compile(r"(?im)^snippets:.*(?:\n[ \t-]+.*)*")  # search snippets of OTHER hosts inside a reader's answer
MULTI_SPLIT = {"blocked", "challenge", "js_wall", "http_402", "login_wall", "not_found", "network", "server_error",
               "needs_auth", "http_error_unknown", "http_other"}  # site-side outcomes that one answer cannot pin to a host
# «Unable to verify if domain X is safe to fetch» = Claude Code's own safety check failed (network/policy), not a ban
_P = lambda p, n, flags=re.I: (re.compile(p, flags), n)
STATUS_PATTERNS = {  # mode -> [(regex, how many leading chars to search)]
    "error": [_P(r"target url returned error (\d{3})", 6000), _P(r"request failed with status code (\d{3})", 6000),
              _P(r"status code does not indicate success: (\d{3})", 6000), _P(r"\"statusCode\"\s*:\s*(\d{3})", 6000),
              _P(r"\"status_code\"\s*:\s*(\d{3})", 6000), _P(r"^HTTP/[\d.]+ (\d{3})", 6000, re.I | re.M),
              _P(r"\bHTTP (\d{3})\b", 6000), _P(r"\((\d{3})\) [A-Z][a-z]+", 6000), _P(r"\bstatus[: ]+(\d{3})\b", 600),
              _P(r"\b(4\d\d|5\d\d) (?:Forbidden|Unauthorized|Not Found|Too Many Requests|Payment Required|"
                 r"Service Unavailable|Bad Gateway)\b", 600)],  # T266: «403 Forbidden: Permission denied by the WAF»
    "content": [_P(r"target url returned error (\d{3})", 2000), _P(r"the server returned http (\d{3})", 300),
                _P(r"\"status\"\s*:\s*(\d{3})\b", 300)],
    # T266: only when the result IS a JSON envelope; a page quoting {"statusCode":404} is not a failure
    "content_json": [_P(r"\"statusCode\"\s*:\s*(\d{3})", 20000), _P(r"\"status_code\"\s*:\s*(\d{3})", 20000)],
    "shell": [_P(r"^HTTP/[\d.]+ (\d{3})", 20000, re.I | re.M), _P(r"status code does not indicate success: (\d{3})", 6000),
              _P(r"\((\d{3})\) [A-Z][a-z]+", 6000), _P(r"request failed with status code (\d{3})", 6000),
              _P(r"returned error: (\d{3})", 6000)],
}
CURL_EXIT = {6: "network", 7: "network", 28: "network", 35: "network", 47: "network", 52: "network", 56: "network",
             60: "network", 22: "http_error_unknown"}  # T266: curl -f exit 22 = an HTTP >= 400 whose code was not printed
PS_NET = ["could not be resolved", "unable to connect to the remote server", "the operation has timed out",
          "no such host is known", "could not establish trust relationship", "the ssl connection could not"]
TITLE_RE = re.compile(r"(?:Page Title|page title|\"title\")\s*[:=]\s*\"?([^\n\"]{0,160})|^title:\s*([^\n]{0,160})",
                      re.M)
ECHO_RE = re.compile(r"(?im)^question:.*(?:\n[ \t]+.*)*")  # jina echoes the caller's question (YAML, may fold; any case)


def title_of(text):
    m = TITLE_RE.search(text[:3000])
    return (m.group(1) or m.group(2) or "") if m else ""


def classify_shell_error(text):
    low = (text or "").lower()
    code = find_status(text, "shell")  # T266: an HTTP status printed by curl outranks a keyword
    if code and code >= 400:
        return status_class(code), code
    if any(w in low for w in PERM):
        return "permission", None
    m = re.search(r"curl: \((\d+)\)", text or "") or re.match(r"\s*Exit code (\d+)\s*$", text or "")
    if m and int(m.group(1)) in CURL_EXIT:
        return CURL_EXIT[int(m.group(1))], None
    if any(w in low for w in PS_NET):
        return "network", None
    return "script_error", None
SECRET_KV = re.compile(r"(key|token|secret|passw\w*|authorization|bearer|cookie)(\s*[:=]\s*)\S+", re.I)


def norm_detail(text: str) -> str:
    t = (text or "")[:500]
    t = URL_RE.sub("<URL>", t)
    t = SECRET_KV.sub(lambda m: m.group(1) + m.group(2) + "<MASK>", t)
    t = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "<EMAIL>", t)
    t = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", t)
    t = re.sub(r"[A-Za-z]:[\\/][^\s\"']+", "<PATH>", t)
    t = re.sub(r"[A-Za-z0-9_\-+/=]{24,}", "<TOK>", t)
    t = re.sub(r"\d{5,}", "<N>", t)
    return re.sub(r"\s+", " ", t).strip()[:140]


def status_class(code: int) -> str:
    if code in (401, 407):  # T266: credentials missing (an API without our key), not a site refusing an agent
        return "needs_auth"
    if code in (403, 429, 451, 999, 418, 406):
        return "blocked"
    if code in (404, 410):
        return "not_found"
    if code == 402:  # T266: x.com answers 402 to anonymous fetches; «paywall» claimed a cause the code does not state
        return "http_402"
    if code >= 500:
        return "server_error"
    if code >= 400:
        return "http_other"
    if 300 <= code < 400:
        return "redirect"
    return "ok"


def find_status(text: str, mode: str = "error"):
    text = text or ""
    pats = STATUS_PATTERNS[mode]
    if mode == "content" and text.lstrip()[:1] in ("{", "["):
        pats = pats + STATUS_PATTERNS["content_json"]
    for rx, n in pats:
        m = rx.search(text[:n])
        if m:
            code = int(m.group(1))
            if 100 <= code <= 999:
                return code
    return None


def classify_error(text: str):
    """T266 order (panel T263): the tool's own refusals and tool-side states first, then an explicit HTTP status,
    then a site's deny page, then network, and the permission keywords only when nothing more specific matched."""
    low = (text or "").lower()
    for group, label in ((POLICY, "tool_policy"), (SERVICE_POLICY, "service_refused"), (ROBOTS, "robots_refused"),
                         (USAGE, "usage"), (TOOL_ENV, "tool_env"), (NET_FIRST, "network")):
        if any(w in low for w in group):
            return label, None
    code = find_status(text or "", "error")
    if code and code >= 400:
        return status_class(code), code
    if any(w in low for w in SITE_DENY):
        return "blocked", None
    if any(w in low for w in PERM):
        return "permission", None
    if any(w in low for w, _kind in NET):
        return "network", None
    return "error_other", None


def classify_content(text: str, title: str = ""):
    """A result the tool did NOT mark as an error: look for block pages and walls.
    Weak words count only in the title or in a SHORT result (a real page carrying them is long)."""
    text = COUNTER_RE.sub("", SNIP_RE.sub("", text or ""))  # T266: a script's counters and other hosts' snippets
    low = text[:6000].lower()
    t = (title or "").lower().strip()
    short = len(text) < 3000
    # T266: a long page ABOUT bot protection is not a challenge page; the markers count on short-ish results only
    if (len(text) < 10000 and any(w in low[:1500] for w in STRONG)) or (short and any(w in low[:400] for w in HEAD_PHRASES)):
        return "challenge"
    if "403 forbidden" in t or (short and "403 forbidden" in low[:300]):
        return "blocked"
    if t and any(w in t for w in WEAK_HEAD):
        return "challenge"
    if short and any(w in low[:300] for w in WEAK_HEAD):
        return "challenge"
    if short and any(w in low[:600] for w in JS_WALL):
        return "js_wall"
    if (short and any(w in low[:600] for w in LOGIN)) or re.match(r"(sign in|log in|login)\b", t):
        return "login_wall"
    return "ok"


# --- URL helpers ------------------------------------------------------------------------------------------------
def urls_from_input(inp):
    out = []
    if isinstance(inp, dict):
        for k in URL_KEYS:
            v = inp.get(k)
            if isinstance(v, str):
                out += URL_RE.findall(v)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str):
                        out += URL_RE.findall(x)
                    elif isinstance(x, dict):
                        out += urls_from_input(x)
        if not out:
            for v in inp.values():
                if isinstance(v, str):
                    out += URL_RE.findall(v)
                elif isinstance(v, (list, dict)):
                    out += urls_from_input(v)
    elif isinstance(inp, list):
        for x in inp:
            out += urls_from_input(x)
    seen, res = set(), []
    for u in out:
        u = u.rstrip(".,:;!?'\"")
        if u not in seen:
            seen.add(u)
            res.append(u)
    return res


def is_local(host: str) -> bool:
    if not host:
        return True
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".test", ".internal", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        return False


def split_url(u: str):
    try:
        s = urlsplit(u)
    except ValueError:
        return None, None
    host = (s.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = s.path or "/"
    return host, f"{s.scheme}://{host}{path}"[:200]


def short_tool(name: str) -> str:
    if name.startswith("mcp__"):
        p = name.split("__")
        server = p[1]
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", server):
            server = "connector"
        server = server.replace("claude_ai_", "").replace("plugin_", "")
        return f"{server}:{p[2] if len(p) > 2 else '?'}"
    return name


# --- source 1: Claude Code transcripts ----------------------------------------------------------------------------
def result_text(block) -> str:
    c = block.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join((p.get("text") or "") for p in c if isinstance(p, dict) and p.get("type") == "text")
    return ""


def scan_transcript(path: str):
    rows = []
    sub = os.sep + "subagents" + os.sep in path
    rel = os.path.relpath(path, CC_ROOT).split(os.sep)
    project = rel[0]
    session = (rel[1] if sub else os.path.splitext(rel[-1])[0])[:8]
    entry = None
    pending = {}
    try:
        fh = open(path, "rb")
    except OSError:
        return rows
    with fh:
        for line in fh:
            if entry is None and b'"entrypoint"' in line[:6000]:
                try:
                    entry = loads(line).get("entrypoint")
                except Exception:
                    pass
            if b"tool_use" not in line and b"tool_result" not in line:
                continue
            try:
                o = loads(line)
            except Exception:
                continue
            # T266: `api-request-blob` lines replay the whole request history (every earlier tool call, no timestamp):
            # 16,847 replayed fetch blocks; they made the undated duplicate rows and the «+2 per host» of the re-test
            if o.get("type") == "api-request-blob":
                continue
            entry = o.get("entrypoint") or entry  # T266: per line, not the file's first value
            content = (o.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for b in content:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    name = b.get("name") or "?"
                    if name in SKIP_TOOLS:
                        continue
                    inp = b.get("input")
                    if name in ("Bash", "PowerShell"):
                        cmd = (inp or {}).get("command", "") if isinstance(inp, dict) else ""
                        if not FETCH_VERB.search(cmd):
                            continue
                        urls = list(dict.fromkeys(URL_RE.findall(cmd)))  # T266: one row per distinct URL
                        if not urls or len(urls) > 8:
                            continue
                    elif name == "WebFetch" or (name.startswith("mcp__") and NAV_TOOL.search(name.split("__")[-1])):
                        urls = urls_from_input(inp)
                    else:
                        continue
                    if urls:
                        pending[b.get("id")] = (name, urls, o.get("timestamp"), entry)
                elif b.get("type") == "tool_result":
                    hit = pending.pop(b.get("tool_use_id"), None)
                    if not hit:
                        continue
                    name, urls, ts, call_entry = hit
                    text = result_text(b)
                    status = None
                    if name in ("Bash", "PowerShell"):
                        if b.get("is_error"):
                            outcome, status = classify_shell_error(text)
                        else:
                            status = find_status(text, "shell")
                            if status and status >= 300:
                                outcome = status_class(status)
                            else:
                                low_sh = COUNTER_RE.sub("", text[:1500]).lower()
                                outcome = "challenge" if any(w in low_sh for w in STRONG) else "ok"
                    elif b.get("is_error"):
                        outcome, status = classify_error(text)
                    elif name == "WebFetch":
                        tur = o.get("toolUseResult")
                        if isinstance(tur, dict) and str(tur.get("code", "")).isdigit():
                            status = int(tur["code"])
                            outcome = status_class(status)
                            if outcome == "ok":
                                outcome = classify_content(text)
                        elif "redirect detected" in text[:400].lower():
                            # T266: a cross-host redirect to a block interstitial (ecfr.gov → unblock.federalregister.gov)
                            targets = " ".join(URL_RE.findall(text[:1500])[1:]).lower()
                            outcome = ("challenge" if re.search(r"unblock|captcha|challenge|/blocked|denied", targets)
                                       else "redirect")
                        else:
                            status = find_status(text, "content")
                            outcome = status_class(status) if status and status >= 300 else classify_content(text)
                    else:
                        text = ECHO_RE.sub("", text)
                        status = find_status(text, "content")
                        if status and status >= 400:
                            outcome = status_class(status)
                        else:
                            outcome = classify_content(text, title_of(text))
                    detail = norm_detail(text) if outcome not in ("ok",) else ""
                    hosts = {split_url(u)[0] for u in urls}
                    for u in urls:
                        host, clean = split_url(u)
                        out_u = outcome
                        # T266: one answer for several hosts says nothing about which host failed
                        if len(hosts) > 1 and outcome in MULTI_SPLIT:  # a tool-side error stays tool-side
                            out_u = "multi_unclear"
                        rows.append({"ts": ts, "surface": "claude-code", "entry": call_entry or "?", "sub": sub,
                                     "project": project, "session": session, "tool": short_tool(name),
                                     "host": host, "url": clean, "outcome": out_u, "status": status,
                                     "detail": detail, "multi": len(urls) > 1, "tid": b.get("tool_use_id"),
                                     "lowconf": name in ("Bash", "PowerShell")})
    return rows


# --- source 2: Claude Desktop MCP logs ----------------------------------------------------------------------------
HDR = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+Z) \[([^\]]*)\] \[([^\]]*)\] (.*)$")
LEVELS = {"info", "error", "warn", "warning", "debug", "trace"}
DEC = json.JSONDecoder()


def desktop_log_files():
    files, seen_servers = [], set()
    roots = []
    for r in DESKTOP_ROOTS:
        if os.path.isdir(r) and os.path.normcase(r) not in [os.path.normcase(x) for x in roots]:
            roots.append(r)
    for r in roots:
        for p in sorted(glob.glob(os.path.join(r, "logs", "mcp-server-*.log*"))):
            files.append((p, "per-server"))
            seen_servers.add(re.sub(r"^mcp-server-|\d*\.log.*$", "", os.path.basename(p)))
    for r in roots:
        for p in sorted(glob.glob(os.path.join(r, "logs", "mcp*.log"))):
            if not os.path.basename(p).startswith("mcp-server-"):
                files.append((p, "aggregate"))
    return files, seen_servers


def parse_desktop_log(path, kind, skip_servers):
    rows = []
    pending = {}

    def handle(ts, server, direction, payload):
        try:
            o, _ = DEC.raw_decode(payload)
        except Exception:
            return
        if not isinstance(o, dict):
            return
        if kind == "aggregate" and server in skip_servers:
            return
        if direction == "client" and o.get("method") == "tools/call":
            params = o.get("params") or {}
            tool = params.get("name") or "?"
            if not NAV_TOOL.search(tool):
                return
            urls = urls_from_input(params.get("arguments"))
            if urls:
                pending[(server, o.get("id"))] = (ts, tool, urls)
        elif direction == "server" and (server, o.get("id")) in pending:
            t0, tool, urls = pending.pop((server, o.get("id")))
            res = o.get("result")
            status = None
            if o.get("error"):
                outcome, status = classify_error(json.dumps(o["error"])[:2000])
                text = json.dumps(o["error"])[:2000]
            else:
                text = ""
                if isinstance(res, dict):
                    text = "\n".join((c.get("text") or "") for c in (res.get("content") or [])
                                     if isinstance(c, dict))
                if isinstance(res, dict) and res.get("isError"):
                    outcome, status = classify_error(text)
                else:
                    text = ECHO_RE.sub("", text)
                    status = find_status(text, "content")
                    if status and status >= 400:
                        outcome = status_class(status)
                    else:
                        outcome = classify_content(text, title_of(text))
            for u in urls:
                host, clean = split_url(u)
                rows.append({"ts": t0, "surface": "desktop-mcp", "entry": "desktop-log", "sub": False,
                             "project": "-", "session": os.path.basename(path)[:24],
                             "tool": short_tool(f"mcp__{server}__{tool}"), "host": host, "url": clean,
                             "outcome": outcome, "status": status,
                             "detail": norm_detail(text) if outcome != "ok" else "", "multi": len(urls) > 1,
                             "lowconf": False, "mcp_full": f"mcp__{server}__{tool}", "raw_url": u})

    cur = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = HDR.match(line.rstrip("\r\n"))
            if m:
                if cur:
                    handle(*cur[:3], "\n".join(cur[3]))
                cur = None
                ts, server, lvl, rest = m.groups()
                if server.lower() in LEVELS:  # the aggregate mcp.log writes [level] [server]
                    server = lvl
                mm = re.match(r"Message from (client|server): (.*)$", rest)
                if mm:
                    cur = [ts, server, mm.group(1), [mm.group(2)]]
            elif cur is not None:
                cur[3].append(line.rstrip("\r\n"))
        if cur:
            handle(*cur[:3], "\n".join(cur[3]))
    return rows


# --- source 3: claude.ai export (experimental) --------------------------------------------------------------------
def scan_claude_export(path):
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.endswith("conversations.json"))
            data = json.loads(z.read(name))
    else:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    rows = []
    for conv in data if isinstance(data, list) else []:
        pending = {}
        for msg in conv.get("chat_messages") or []:
            for b in msg.get("content") or []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    urls = urls_from_input(b.get("input"))
                    if urls:
                        pending[b.get("id") or b.get("name")] = (b.get("name") or "?", urls,
                                                                  b.get("start_timestamp") or msg.get("created_at"))
                elif b.get("type") == "tool_result":
                    hit = pending.pop(b.get("tool_use_id"), None) or pending.pop(b.get("name"), None)
                    if not hit:
                        continue
                    name, urls, ts = hit
                    c = b.get("content")
                    text = c if isinstance(c, str) else json.dumps(c)[:6000]
                    if b.get("is_error"):
                        outcome, status = classify_error(text)
                    else:
                        status = None
                        outcome = classify_content(text)
                    for u in urls:
                        host, clean = split_url(u)
                        rows.append({"ts": ts, "surface": "claude-ai-export", "entry": "claude.ai", "sub": False,
                                     "project": "-", "session": (conv.get("uuid") or "?")[:8], "tool": name,
                                     "host": host, "url": clean, "outcome": outcome, "status": status,
                                     "detail": norm_detail(text) if outcome != "ok" else "", "multi": len(urls) > 1,
                                     "lowconf": False})
    return rows


# --- aggregation and report ---------------------------------------------------------------------------------------
def dedupe_calls(rows):
    """T266 (panel T263, DeepSeek + GLM + Grok Build): one tool call = one row per URL. The same tool_use id appears
    again in later lines of a transcript (37,034 copies in `assistant` lines) and in other files (243 ids: forks,
    resumed sessions). Keep the earliest dated copy of each (id, url)."""
    best = {}
    rest = []
    for r in rows:
        tid = r.get("tid")
        if not tid:
            rest.append(r)
            continue
        k = (tid, r["url"])
        cur = best.get(k)
        if cur is None or (r["ts"] and (not cur["ts"] or r["ts"] < cur["ts"])):
            best[k] = r
    return list(best.values()) + rest


def mark_twins(desk, cc):
    idx = collections.defaultdict(list)
    for r in cc:
        if r["tool"] and r["ts"]:
            idx[(r["tool"], r["url"])].append(r["ts"])
    for v in idx.values():
        v.sort()
    twins = 0
    for r in desk:
        lst = idx.get((r["tool"], r["url"]), [])
        i = bisect.bisect_left(lst, r["ts"][:16])
        near = [x for x in lst[max(0, i - 3):i + 3] if abs(_secs(x) - _secs(r["ts"])) <= 300]
        r["twin"] = bool(near)
        twins += r["twin"]
    return twins


def _secs(ts):
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0


GROUPS = [("blocked by the site (403/429/451/999, challenge page, JS wall)", {"blocked", "challenge", "js_wall"}),
          ("HTTP 402 (payment required: a paywall or a bot gate; the code does not say which)", {"http_402"}),
          ("refused by Claude Code's own list (WebFetch preflight)", {"tool_policy"}),
          ("refused by a fetch service or by the site's robots.txt", {"service_refused", "robots_refused"}),
          ("needs a key or a login (401/407)", {"needs_auth"}),
          ("network or server error", {"network", "server_error"}),
          ("login wall", {"login_wall"}),
          ("not found: a wrong or private URL (a bot may also get 404)", {"not_found"}),
          ("unclear: HTTP error without its code, or one answer for several hosts",
           {"http_error_unknown", "multi_unclear"})]
CANNOT = {"blocked", "challenge", "http_402", "js_wall", "tool_policy", "service_refused", "robots_refused",
          "needs_auth", "network", "server_error", "login_wall"}
TOOL_SIDE = {"tool_env", "permission", "usage", "error_other", "script_error"}


def report_v2(rows, out_dir, meta, top):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "attempts.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps({k: v for k, v in r.items() if k != "raw_url"}, ensure_ascii=False) + "\n")
    fmt = lambda c, n: "; ".join(f"{k}×{v}" for k, v in c.most_common(n))
    by_host = collections.defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r)
    ok_tools = {h: collections.Counter(r["tool"] for r in rs if r["outcome"] == "ok") for h, rs in by_host.items()}
    oc = collections.Counter(r["outcome"] for r in rows)
    lines = ["# Sites an AI agent failed to open: local scan", "",
             "Private: built from local transcripts and logs. URLs carry no query strings. Never publish.", "",
             "## Sources", ""] + [f"- {k}: {v}" for k, v in meta.items()]
    lines += ["", "## Outcomes", ""] + [f"- {k}: {v}" for k, v in oc.most_common()]
    print("outcomes: " + ", ".join(f"{k}={v}" for k, v in oc.most_common()))
    surf = collections.defaultdict(collections.Counter)
    for r in rows:
        surf[r["entry"]]["attempts"] += 1
        surf[r["entry"]]["cannot_open"] += r["outcome"] in CANNOT
    print("by surface (entrypoint): " + "; ".join(f"{k} {v['attempts']} attempts, {v['cannot_open']} could not open"
                                                 for k, v in sorted(surf.items(), key=lambda kv: -kv[1]['attempts'])))
    for title, classes in GROUPS:
        tab = []
        for h, rs in by_host.items():
            f = [r for r in rs if r["outcome"] in classes]
            if f:
                tab.append((len(f), h, collections.Counter(r["outcome"] + (f" {r['status']}" if r["status"] else "")
                                                           for r in f),
                            collections.Counter(r["tool"] for r in f), ok_tools[h],
                            collections.Counter(r["entry"] for r in f), max(r["ts"] or "" for r in f)[:10],
                            len({(r["project"], r["session"]) for r in f})))
        tab.sort(key=lambda x: (-x[0], x[1]))
        total = sum(x[0] for x in tab)
        lines += ["", f"## {title}: {total} attempts on {len(tab)} hosts", "",
                  "| host | failed | sessions | kinds | failed with | opened with (any time) | surfaces | last |",
                  "|---|---|---|---|---|---|---|---|"]
        lines += [f"| {x[1]} | {x[0]} | {x[7]} | {fmt(x[2], 4)} | {fmt(x[3], 5)} | {fmt(x[4], 4) or '—'} | "
                  f"{fmt(x[5], 3)} | {x[6]} |" for x in tab[:400]]
        n = top if "blocked" in classes else (12 if "not_found" not in classes else 6)
        print(f"\n== {title}: {total} attempts on {len(tab)} hosts")
        for x in tab[:n]:
            print(f"  {mask_ip(x[1])[:28]:28s} {x[0]:3d} | {fmt(x[2], 2)[:30]:30s} | failed: {fmt(x[3], 2)[:44]:44s}"
                  f" | opened: {fmt(x[4], 2)[:50] or '—'}")
    never = []
    for h, rs in by_host.items():
        f = [r for r in rs if r["outcome"] in CANNOT]
        if f and not ok_tools[h]:
            never.append((len(f), h, collections.Counter(r["tool"] for r in f), collections.Counter(r["outcome"] for r in f)))
    never.sort(key=lambda x: (-x[0], x[1]))
    lines += ["", f"## Never opened by any tool: {len(never)} hosts", ""]
    lines += [f"- {x[1]}: {x[0]} failed ({fmt(x[3], 3)}); tried {fmt(x[2], 5)}" for x in never]
    print(f"\n== never opened by any tool: {len(never)} hosts (failed attempts; kinds; tools tried)")
    for x in never[:top]:
        print(f"  {mask_ip(x[1])[:30]:30s} {x[0]:3d} | {fmt(x[3], 2)[:28]:28s} | {fmt(x[2], 4)[:80]}")
    chains, seen, examples = collections.Counter(), set(), collections.defaultdict(list)
    by_url = collections.defaultdict(list)
    for r in rows:
        if r["surface"] == "claude-code":
            by_url[(r["project"], r["session"], r["url"])].append(r)
    for key, rs in by_url.items():
        rs.sort(key=lambda r: r["ts"] or "")
        for i, r in enumerate(rs):
            if r["outcome"] in CANNOT or r["outcome"] == "not_found":
                for r2 in rs[i + 1:]:
                    if r2["outcome"] == "ok" and r2["tool"] != r["tool"]:
                        pair = (r["tool"], r2["tool"])
                        if (key, pair) not in seen:
                            seen.add((key, pair))
                            chains[pair] += 1
                            if r["host"] not in examples[pair] and len(examples[pair]) < 4:
                                examples[pair].append(r["host"])
                        break
    lines += ["", "## Rescue chains: the same URL failed with A, then B opened it in the same session", ""]
    lines += [f"- {a} → {b}: {n} (e.g. {', '.join(examples[(a, b)])})" for (a, b), n in chains.most_common(40)]
    print("\n== rescue chains (same URL, same session): failed with → opened with")
    for (a, b), n in chains.most_common(12):
        print(f"  {n:4d}  {a} → {b}  (e.g. {', '.join(mask_ip(h) for h in examples[(a, b)][:3])})")
    ts_ = collections.defaultdict(collections.Counter)
    for r in rows:
        c = ts_[r["tool"]]
        c["attempts"] += 1
        c["ok"] += r["outcome"] == "ok"
        c["cannot_open"] += r["outcome"] in CANNOT
        c["not_found"] += r["outcome"] == "not_found"
        c["tool_side"] += r["outcome"] in TOOL_SIDE
    lines += ["", "## Tools", "", "| tool | attempts | ok | could not open | not found | tool-side errors |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {t} | {c['attempts']} | {c['ok']} | {c['cannot_open']} | {c['not_found']} | {c['tool_side']} |"
              for t, c in sorted(ts_.items(), key=lambda kv: -kv[1]["attempts"])]
    print("\n== tools: attempts / ok / could not open / not found / tool-side errors")
    for t, c in sorted(ts_.items(), key=lambda kv: -kv[1]["attempts"])[:16]:
        print(f"  {t[:40]:40s} {c['attempts']:6d} {c['ok']:6d} {c['cannot_open']:5d} {c['not_found']:5d} {c['tool_side']:5d}")
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return chains


def mask_ip(h):
    try:
        ipaddress.ip_address(h.strip("[]"))
        return "<ip>"
    except ValueError:
        return h


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "report"))
    ap.add_argument("--since", default="")
    ap.add_argument("--until", default="", help="freeze the corpus: drop rows at or after this UTC time (T266)")
    ap.add_argument("--include-local", action="store_true")
    ap.add_argument("--claude-export", default="")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    t0 = time.time()
    files = glob.glob(os.path.join(CC_ROOT, "**", "*.jsonl"), recursive=True)
    files.sort(key=os.path.getsize, reverse=True)
    cc = []
    with ProcessPoolExecutor(max_workers=max(1, min(8, (os.cpu_count() or 2) - 1))) as ex:
        for rs in ex.map(scan_transcript, files, chunksize=4):
            cc += rs
    raw_cc = len(cc)
    cc = dedupe_calls(cc)
    dfiles, per_server = desktop_log_files()
    desk = []
    for p, kind in dfiles:
        desk += parse_desktop_log(p, kind, per_server)
    twins = mark_twins(desk, cc)
    exp = scan_claude_export(args.claude_export) if args.claude_export else []
    rows = cc + [r for r in desk if not r.get("twin")] + exp
    rows = [r for r in rows if r["host"] and (args.include_local or not is_local(r["host"]))]
    if args.since:
        rows = [r for r in rows if (r["ts"] or "") >= args.since]
    if args.until:
        rows = [r for r in rows if (r["ts"] or "") < args.until]
    ent = collections.Counter(r["entry"] for r in rows)
    meta = {"Claude Code transcripts": f"{len(files)} files, {len(cc)} URL attempts after removing "
                                       f"{raw_cc - len(cc)} copies of the same tool call (same tool_use id)",
            "frozen at": args.until or "not frozen (corpus still growing)",
            "entrypoints in kept rows": dict(ent),
            "Desktop MCP logs": f"{len(dfiles)} files, {len(desk)} URL attempts, {twins} also in a transcript "
                                f"(dropped as twins), {len(desk) - twins} Desktop-only",
            "claude.ai export": f"{len(exp)} attempts" if args.claude_export else "not given",
            "date range": f"{min((r['ts'] or '9') for r in rows)[:10]} .. {max((r['ts'] or '') for r in rows)[:10]}"
            if rows else "-", "local/private hosts": "kept" if args.include_local else "dropped"}
    print(f"scan {time.time() - t0:.1f} s; rows kept {len(rows)}, hosts {len({r['host'] for r in rows})}")
    for k, v in meta.items():
        print(f"  {k}: {v}")
    report_v2(rows, args.out, meta, args.top)
    print(f"\nreport: {os.path.join(args.out, 'report.md')}")
    print("VERDICT: OK" if rows else "VERDICT: FAIL no rows")
    return 0 if rows else 1


# --- selftest: synthetic fixtures, positive AND negative -----------------------------------------------------------
def selftest():
    import tempfile
    cases = []

    def tu(i, name, inp):
        return {"type": "assistant", "timestamp": f"2026-11-01T10:00:{i:02d}Z", "entrypoint": "cli",
                "message": {"content": [{"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}]}}

    def tr(i, text, err=False, tur=None):
        o = {"type": "user", "timestamp": f"2026-11-01T10:00:{i:02d}Z",
             "message": {"content": [{"type": "tool_result", "tool_use_id": f"t{i}", "content": text,
                                      **({"is_error": True} if err else {})}]}}
        if tur is not None:
            o["toolUseResult"] = tur
        return o

    wf = lambda code: {"bytes": 10, "code": code, "codeText": "x", "durationMs": 5, "result": "r", "url": "u"}
    spec = [  # (tool, input, result text, is_error, toolUseResult, expected outcome, expected status)
        ("WebFetch", {"url": "https://ok.example.org/a?x=SECRET"}, "Docs about Cloudflare login and sign in pages",
         False, wf(200), "ok", 200),
        ("WebFetch", {"url": "https://blocked.example.org/"}, "Forbidden", False, wf(403), "blocked", 403),
        ("WebFetch", {"url": "https://www.reddit.com/r/x"}, "Claude Code is unable to fetch from www.reddit.com",
         True, None, "tool_policy", None),
        ("WebFetch", {"url": "https://perm.example.org/"},
         "Claude requested permissions to use WebFetch, but you haven't granted it yet.", True, None,
         "permission", None),
        ("WebFetch", {"url": "https://cf.example.org/"}, "Just a moment... Enable JavaScript and cookies to continue",
         False, wf(200), "challenge", 200),
        ("WebFetch", {"url": "https://gone.example.org/x"}, "Not Found", False, wf(404), "not_found", 404),
        ("mcp__jina-mcp-server__read_url", {"url": "https://blocked.example.org/"},
         "Warning: Target URL returned error 403: Forbidden", False, None, "blocked", 403),
        ("mcp__jina-mcp-server__read_url", {"url": "https://blocked.example.org/"}, "# Title\nreal content here",
         False, None, "ok", None),
        ("mcp__playwright__browser_navigate", {"url": "https://cf.example.org/"},
         "### Page state\n- Page URL: https://cf.example.org/\n- Page Title: Just a moment...", False, None,
         "challenge", None),
        ("mcp__playwright__browser_navigate", {"url": "https://busy.example.org/"},
         "### Error\nError: Browser is already in use for /tmp/profile-x, use --isolated", True, None, "tool_env", None),
        ("mcp__firecrawl__firecrawl_scrape", {"url": "https://busy.example.org/"},
         "Tool 'firecrawl_scrape' execution failed: Insufficient credits", True, None, "tool_env", None),
        ("Bash", {"command": "curl -sI https://curl.example.org/ | head -1"}, "HTTP/2 403", False, None, "blocked",
         403),
        ("Bash", {"command": "git push https://github.com/x/y.git main"}, "Exit code 1", True, None, None, None),
        ("WebFetch", {"url": "http://localhost:4321/"}, "ECONNREFUSED", True, None, "network", None),
        ("mcp__jina-mcp-server__read_url", {"url": "https://slow.example.org/"},
         "The operation was aborted due to timeout", True, None, "network", None),
        ("WebFetch", {"url": "https://nocode.example.org/"},
         "The server returned HTTP 403 Forbidden. The response body was not retrieved.", False, None, "blocked", 403),
        ("mcp__jina-mcp-server__read_url", {"url": "https://echo.example.org/"},
         "url: https://echo.example.org/\ntitle: Pricing\nquestion: does it pass bot protection or a challenge page?\n"
         "content: " + "real text " * 400, False, None, "ok", None),
        ("mcp__jina-mcp-server__read_url", {"url": "https://t403.example.org/"},
         "url: https://t403.example.org/\ntitle: 403 Forbidden\ncontent: 403 Forbidden", False, None, "blocked", None),
        ("Bash", {"command": "curl -s https://script.example.org/ | python -c 'import json'"},
         "Exit code 1\nTraceback (most recent call last): timed out", True, None, "script_error", None),
        ("Bash", {"command": "curl -sf https://c22.example.org/"}, "Exit code 22", True, None, "http_error_unknown",
         None),
        ("WebFetch", {"url": "https://check.example.org/"},
         "Unable to verify if domain check.example.org is safe to fetch. This may be due to network restrictions or "
         "enterprise security policies blocking claude.ai.", True, None, "tool_env", None),
        # --- T266 negative fixtures from the T263 panel (each one a wrong class before) ---
        ("WebFetch", {"url": "https://api.example.org/v1"}, "Unauthorized", False, wf(401), "needs_auth", 401),
        ("mcp__jina-mcp-server__read_url", {"url": "https://pay.example.org/"},
         "Target URL returned error 402: Payment Required", True, None, "http_402", 402),
        ("mcp__jina-mcp-server__read_url", {"url": "https://cfb.example.org/"}, "Error: blocked by Cloudflare", True,
         None, "blocked", None),
        ("mcp__jina-mcp-server__read_url", {"url": "https://waf.example.org/"},
         "403 Forbidden: Permission denied by the site WAF", True, None, "blocked", 403),
        ("mcp__firecrawl__firecrawl_scrape", {"url": "https://fcp.example.org/"},
         "Tool 'firecrawl_scrape' execution failed: We apologize for the inconvenience but we do not support this "
         "site", True, None, "service_refused", None),
        ("mcp__jina-mcp-server__read_url", {"url": "https://echo2.example.org/"},
         "url: https://echo2.example.org/\ntitle: Pricing\nQuestion: does it pass bot protection or a challenge page?\n"
         "content: " + "real text " * 400, False, None, "ok", None),
        ("Bash", {"command": "curl -s https://cnt.example.org/ | python count.py"},
         "HTTP 200 18B Page2AI: 18 1.0.0: 24 Just a moment: 0 cf-chl: 0", False, None, "ok", None),
        ("WebFetch", {"url": "https://docs.example.org/bots"},
         "This documentation describes bot protection and how a challenge page works. " + "Reference text. " * 300,
         False, wf(200), "ok", 200),
        ("mcp__jina-mcp-server__read_url", {"url": "https://json.example.org/errors"},
         "# Error codes\nA missing record answers {\"statusCode\":404,\"error\":\"Not Found\"}. " + "More docs. " * 200,
         False, None, "ok", None),
        ("WebFetch", {"url": "https://ecfr.example.org/x"},
         "REDIRECT DETECTED: The URL redirects to a different host.\n\nOriginal URL: https://ecfr.example.org/x\n"
         "Redirect URL: https://unblock.example.org/?t=1\nStatus: 302 Found", False, None, "challenge", None),
        ("mcp__jina-mcp-server__parallel_read_url", {"urls": ["https://m1.example.org/a", "https://m2.example.org/b"]},
         "Target URL returned error 403: Forbidden", True, None, "multi_unclear", 403),
    ]
    with tempfile.TemporaryDirectory() as d:
        proj = os.path.join(d, "projects", "P")
        os.makedirs(proj)
        p = os.path.join(proj, "sess0001.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            for i, (name, inp, text, err, tur, _o, _s) in enumerate(spec):
                fh.write(json.dumps(tu(i, name, inp)) + "\n")
                fh.write(json.dumps(tr(i, text, err, tur)) + "\n")
            # T266: the same call written again later (a replay) and an api-request-blob replay of another call
            fh.write(json.dumps(dict(tu(1, spec[1][0], spec[1][1]), timestamp="2026-11-01T11:00:00Z")) + "\n")
            fh.write(json.dumps(dict(tr(1, spec[1][2], spec[1][3], spec[1][4]), timestamp="2026-11-01T11:00:00Z")) + "\n")
            fh.write(json.dumps({"type": "api-request-blob", "message": {"content": [
                {"type": "tool_use", "id": "tb1", "name": "WebFetch", "input": {"url": "https://blob.example.org/"}},
                {"type": "tool_result", "tool_use_id": "tb1", "content": "Forbidden"}]}}) + "\n")
        global CC_ROOT
        old = CC_ROOT
        CC_ROOT = os.path.join(d, "projects")
        rows = dedupe_calls(scan_transcript(p))
        CC_ROOT = old
        ok = True
        good = (sum(1 for r in rows if r["host"] == "blocked.example.org" and r["tool"] == "WebFetch") == 1
                and not any(r["host"] == "blob.example.org" for r in rows))
        cases.append(("a replayed call counts once; an api-request-blob replay not at all", good))
        ok &= good
        by_host = collections.defaultdict(list)
        for r in rows:
            by_host[(r["tool"], r["host"])].append(r)
        for i, (name, inp, text, err, tur, exp_o, exp_s) in enumerate(spec):
            host, _ = split_url(urls_from_input(inp)[0] if name not in ("Bash",) else URL_RE.findall(inp["command"])[0])
            got = [r for r in rows if r["ts"] == f"2026-11-01T10:00:{i:02d}Z"]
            if exp_o is None:
                good = not got
                cases.append((f"{name} {host}: not counted", good))
            else:
                good = bool(got) and got[0]["outcome"] == exp_o and got[0]["status"] == exp_s
                cases.append((f"{name} {host}: {exp_o} {exp_s} (got {got[0]['outcome'] if got else None} "
                              f"{got[0]['status'] if got else None})", good))
            ok &= good
        leak = any("SECRET" in json.dumps(r) for r in rows)
        cases.append(("no query string kept", not leak))
        ok &= not leak
        cases.append(("localhost dropped by default", is_local("localhost") and not is_local("example.org")))
        # rescue chain: WebFetch 403 then jina ok on blocked.example.org
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            chains = report_v2(rows, os.path.join(d, "out"), {"selftest": 1}, 5)
        good = chains.get(("WebFetch", "jina-mcp-server:read_url"), 0) == 1
        cases.append(("rescue chain WebFetch → jina", good))
        ok &= good
        # desktop log: multi-line JSON, a call and an isError answer
        lp = os.path.join(d, "mcp-server-jina-mcp-server.log")
        with open(lp, "w", encoding="utf-8") as fh:
            fh.write('2026-11-01T10:00:00.000Z [jina-mcp-server] [info] Message from client: {"method":"tools/call",'
                     '"params":{"name":"read_url","arguments":{\n"url":"https://d.example.org/p"}},"jsonrpc":"2.0",'
                     '"id":7} { metadata: undefined }\n')
            fh.write('2026-11-01T10:00:02.000Z [jina-mcp-server] [info] Message from server: {"jsonrpc":"2.0","id":7,'
                     '"result":{"content":[{"type":"text","text":"HTTP 451: Unavailable For Legal Reasons"}],'
                     '"isError":true}} { metadata: undefined }\n')
        drows = parse_desktop_log(lp, "per-server", set())
        good = len(drows) == 1 and drows[0]["outcome"] == "blocked" and drows[0]["status"] == 451
        cases.append((f"desktop log multi-line call + isError → blocked 451 (got {[(r['outcome'], r['status']) for r in drows]})",
                      good))
        ok &= good
    for name, good in cases:
        print(("PASS " if good else "FAIL ") + name)
    print(f"VERDICT: {'OK' if ok else 'FAIL'} ({sum(g for _, g in cases)}/{len(cases)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
