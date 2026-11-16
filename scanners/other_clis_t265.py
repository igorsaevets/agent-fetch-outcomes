# T265: which sites OpenCode, Codex, Antigravity CLI/IDE and MiMo Code failed to open, and with which tool.
# Reuses the classifier of fetch_failures.py (keep both files in one folder) so the classes match the
# Claude Code report. Reads every store read-only; prints counts, classes and normalized error shapes only.
#   python -X utf8 other_clis_t265.py [--only opencode,codex,agy,mimo] [--out <dir>] [--until <ISO UTC>]
#                                     [--mimo-db <path to mimocode.db>]   (MiMo is skipped without it)
import argparse
import collections
import datetime as dt
import json
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fetch_failures as ff  # noqa: E402

H = pathlib.Path.home()
OC_DB = H / ".local/share/opencode/opencode.db"
MIMO_DB = None  # MiMo Code keeps its SQLite file where it was installed: pass --mimo-db <path>
CX_HIST = H / ".codex/thread_history_1.sqlite"
CX_STATE = H / ".codex/state_5.sqlite"
AGY = {"agy-cli": (H / ".gemini/antigravity-cli/conversations", H / ".gemini/antigravity-cli/conversation_summaries.db"),
       "agy-ide": (H / ".gemini/antigravity/conversations", H / ".gemini/antigravity/conversation_summaries.db")}
SHELL_NAMES = {"shell", "bash", "execute", "powershell", "Bash", "PowerShell"}
# Sessions started by a review harness in its own workspace folder (named *-ws or *-review-panel) are flagged.
PANEL_RX = re.compile(r"(orch-[a-z0-9]+-ws|[a-z0-9]+-ws[\\/]|-review-panel)", re.I)
SKIP_NAME = re.compile(r"search|feedback|_status|usage|credit|list_|_tabs$|snapshot|evaluate|click|type$|press|"
                       r"screenshot|wait|close|launch|console|network|resize|hover|select|drag|upload", re.I)


def ro(p):
    return sqlite3.connect(f"file:{pathlib.Path(p).as_posix()}?mode=ro", uri=True, timeout=10)


def iso_ms(ms):
    try:
        return dt.datetime.fromtimestamp(int(ms) / 1000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return None


# T265 additions, each from a sampled error shape: agy's Go stack trace carries words like «permission» (81 HTTP
# errors read as permission), a URL path can carry a keyword, and three status formats the T262 patterns miss.
STACK = re.compile(r"\(\d+\) attached stack trace.*|-- stack trace:.*", re.S)
EXTRA_STATUS = [re.compile(r"non 2xx status code \((\d{3}) ", re.I),          # opencode / MiMo webfetch
                re.compile(r"failed to get URL \S+ status code (\d{3})", re.I),  # Antigravity read_url_content
                re.compile(r"Invoke-(?:WebRequest|RestMethod) :[^\n]{0,160}?\((\d{3})\)", re.I)]  # localized PS
CANCEL = ("user cancelled mcp tool call", "tool call cancelled because an earlier tool call")
BUILTIN = {"webfetch", "read_url_content", "WebFetch(cc-compat)"}  # error on non-2xx: page text is never a status


def clean(text):
    return ff.URL_RE.sub("<URL>", STACK.sub("", text or ""))


def classify_err(text):
    for rx in EXTRA_STATUS:
        m = rx.search((text or "")[:4000])
        if m and int(m.group(1)) >= 400:
            return ff.status_class(int(m.group(1))), int(m.group(1))
    t = clean(text)
    low = t.lower()
    if any(w in low for w in CANCEL) or "interaction cancelled because the location shut down" in low:
        return "tool_env", None
    if "ssrf protection" in low:  # MiMo Code's webfetch guard: private address = the tool's policy, DNS = network
        return ("network", None) if "dns resolution failed" in low else ("tool_policy", None)
    if "unsupported fetched file content type" in low:  # the tool cannot read that type (PDF)
        return "tool_env", None
    out, st = ff.classify_error(t)
    if out == "error_other" and any(w in low for w in ("transport error", "no such host", "dial tcp")):
        return "network", None
    return out, st


def judge_fetch(is_error, text, title="", builtin=False):
    """A fetch-like tool (built-in or MCP): error text, else the returned page."""
    if is_error:
        return classify_err(text)
    text = ff.ECHO_RE.sub("", text or "")
    st = None if builtin else ff.find_status(text, "content")
    if st and st >= 400:
        return ff.status_class(st), st
    return ff.classify_content(text, title or ff.title_of(text)), None


def judge_shell(is_error, text, exit_code=None, cmd=""):
    for rx in EXTRA_STATUS[2:]:
        m = rx.search(text or "")
        if m and int(m.group(1)) >= 400:
            return ff.status_class(int(m.group(1))), int(m.group(1))
    if is_error:
        out, st = ff.classify_shell_error(clean(text))
        if out == "script_error" and re.search(r"\bcurl", cmd, re.I) and exit_code in ff.CURL_EXIT:
            out = ff.CURL_EXIT[exit_code]
        return out, st
    st = ff.find_status(text or "", "shell")
    if st and st >= 300:
        return ff.status_class(st), st
    low_sh = ff.COUNTER_RE.sub("", (text or "")[:1500]).lower()  # T266: a script's counters are not a challenge
    return ("challenge" if any(w in low_sh for w in ff.STRONG) else "ok"), None


def mark_multi(rows):
    """T266 (panel T263): one answer for several hosts says nothing about which host failed."""
    calls = collections.defaultdict(list)
    for r in rows:
        if r.get("multi"):
            calls[(r["surface"], r["session"], r["ts"], r["tool"])].append(r)
    n = 0
    for rs in calls.values():
        if len({r["host"] for r in rs}) > 1:
            for r in rs:
                if r["outcome"] in ff.MULTI_SPLIT:  # a tool-side error (cancelled, credits) stays tool-side
                    r["outcome"] = "multi_unclear"
                    n += 1
    return n


def shell_urls(cmd):
    if not isinstance(cmd, str):
        cmd = " ".join(cmd) if isinstance(cmd, list) else ""
    if not ff.FETCH_VERB.search(cmd):
        return []
    urls = list(dict.fromkeys(ff.URL_RE.findall(cmd)))  # T266: distinct URLs, same cap as the T262 scanner
    return urls if 0 < len(urls) <= 8 else []


def is_nav(name):
    low = name.lower()
    if low in ("webfetch", "web_fetch", "read_url_content"):
        return True
    if SKIP_NAME.search(low):
        return False
    return bool(ff.NAV_TOOL.search(low) or low.endswith("_get") or low == "get")


def row(cli, entry, session, tool, url, outcome, status, text, ts, panel, model=None, multi=False):
    host, clean = ff.split_url(url)
    return {"ts": ts, "surface": cli, "entry": entry, "sub": False, "project": "-", "session": str(session)[:40],
            "tool": tool, "host": host, "url": clean, "outcome": outcome, "status": status,
            "detail": ff.norm_detail(text) if outcome != "ok" else "", "multi": multi, "panel": panel,
            "model": model}


def text_of(v):
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(text_of(x) for x in v)
    if isinstance(v, dict):
        return text_of(v.get("text") or v.get("content") or v.get("output") or v.get("message") or "")
    return ""


# ---------------------------------------------------------------- OpenCode (v2) and MiMo Code (v1 parts)
def tool_rows(cli, entry, session, name, state, ts, panel, model, stats):
    status = (state or {}).get("status")
    inp = (state or {}).get("input") or {}
    meta = (state or {}).get("metadata") or {}
    err = state.get("error")
    err_text = err.get("message", "") if isinstance(err, dict) else (err or "")
    out_text = text_of(state.get("content")) or text_of(state.get("output")) or ""
    stats[f"{cli}:tool:{name}"] += 1
    rows = []
    if name in SHELL_NAMES:
        cmd = inp.get("command") if isinstance(inp, dict) else ""
        urls = shell_urls(cmd or "")
        if not urls:
            return rows
        exit_code = meta.get("exit") if isinstance(meta, dict) else None
        text = err_text or text_of(meta.get("output")) or out_text
        is_error = status == "error" or (isinstance(exit_code, int) and exit_code != 0)
        outcome, st = judge_shell(is_error, text, exit_code, cmd if isinstance(cmd, str) else "")
        tool = "curl(shell)"
    elif is_nav(name):
        urls = ff.urls_from_input(inp)
        if not urls:
            return rows
        outcome, st = judge_fetch(status == "error", err_text if status == "error" else out_text,
                                  builtin=name in BUILTIN)
        tool = name
    else:
        return rows
    if status not in ("completed", "error"):  # «running»/«pending» = never finished (T265 cross-check: 2 in MiMo)
        outcome, st, err_text = "tool_env", None, f"unfinished tool call (status {status})"
    for u in urls:
        rows.append(row(cli, entry, session, tool, u, outcome, st, err_text or out_text, ts, panel, model,
                        len(urls) > 1))
    return rows


def scan_opencode(stats):
    con = ro(OC_DB)
    dirs = dict(con.execute("select id, directory from session_v2"))
    rows = []
    for sid, created, data in con.execute("select session_id, time_created, data from session_message "
                                          "where type='assistant' and data like '%\"type\":\"tool\"%'"):
        try:
            d = json.loads(data)
        except ValueError:
            continue
        m = d.get("model")
        model = (m.get("modelID") or m.get("id")) if isinstance(m, dict) else m
        panel = bool(PANEL_RX.search(dirs.get(sid) or ""))
        for it in d.get("content") or []:
            if isinstance(it, dict) and it.get("type") == "tool":
                t = (it.get("time") or {}).get("created") or created
                rows += tool_rows("opencode", "opencode-panel" if panel else "opencode", sid, it.get("name") or "?",
                                  it.get("state") or {}, iso_ms(t), panel, model, stats)
    stats["opencode:sessions"] = len(dirs)
    con.close()
    return rows


def scan_mimo(stats):
    con = ro(MIMO_DB)
    imported = {r[0] for r in con.execute("select session_id from external_import")}
    dirs = dict(con.execute("select id, directory from session"))
    models = {}
    for mid, data in con.execute("select id, data from message where data like '%modelID%'"):
        try:
            models[mid] = json.loads(data).get("modelID")
        except ValueError:
            pass
    rows = []
    for sid, mid, created, data in con.execute(
            "select session_id, message_id, time_created, data from part "
            "where json_extract(data,'$.type')='tool' and data like '%http%'"):
        if sid in imported:
            stats["mimo:skipped_imported_cc"] += 1
            continue
        try:
            d = json.loads(data)
        except ValueError:
            continue
        st = d.get("state") or {}
        t = ((st.get("time") or {}).get("start")) or created
        panel = bool(PANEL_RX.search(dirs.get(sid) or ""))
        name = d.get("tool") or "?"
        if name.startswith("mcp__"):
            name = ff.short_tool(name)
        if name == "WebFetch":
            name = "WebFetch(cc-compat)"
        rows += tool_rows("mimo", "mimo-panel" if panel else "mimo", sid, name, st, iso_ms(t), panel,
                          models.get(mid), stats)
    stats["mimo:sessions_native"] = len(set(dirs) - imported)
    stats["mimo:sessions_imported_cc"] = len(imported)
    con.close()
    return rows


# ---------------------------------------------------------------- Codex (thread_history projection)
def scan_codex(stats):
    st = ro(CX_STATE)
    th = {}
    for tid, source, orig, cwd, ver, model in st.execute(
            "select id, source, originator, cwd, cli_version, model from threads"):
        s = source or "?"
        kind = ("exec" if s == "exec" else "cli" if s == "cli" else "app" if s == "vscode"
                else "subagent" if s.startswith("{") else s)
        th[tid] = ("codex-" + kind, bool(PANEL_RX.search(cwd or "")), ver, model)
    st.close()
    con = ro(CX_HIST)
    rows = []
    for tid, created, itype, j in con.execute(
            "select thread_id, created_at_ms, item_type, item_json from thread_items "
            "where item_type in ('webSearch','mcpToolCall','commandExecution')"):
        entry, panel, ver, model = th.get(tid, ("codex-?", False, None, None))
        ts = iso_ms(created)
        try:
            o = json.loads(j)
        except ValueError:
            continue
        if itype == "webSearch":
            act = o.get("action") or {}
            stats[f"codex:web_search:{act.get('type')}"] += 1
            if act.get("type") in ("openPage", "findInPage") and act.get("url"):
                tool = "web_search:" + ("open_page" if act["type"] == "openPage" else "find_in_page")
                rows.append(row("codex", entry, tid, tool, act["url"], "unrecorded", None, "", ts, panel, model))
            continue
        if itype == "commandExecution":
            cmd = o.get("command") or ""
            urls = shell_urls(cmd)
            if not urls:
                continue
            code = o.get("exitCode")
            out = o.get("aggregatedOutput") or ""
            outcome, sc = judge_shell(isinstance(code, int) and code != 0, out, code,
                                      cmd if isinstance(cmd, str) else " ".join(cmd))
            for u in urls:
                rows.append(row("codex", entry, tid, "curl(shell)", u, outcome, sc, out, ts, panel, model,
                                len(urls) > 1))
            continue
        server, tool, status = o.get("server") or "?", o.get("tool") or "?", o.get("status")
        stats[f"codex:mcp:{server}:{tool}"] += 1
        if server in ("node_repl", "cua_repl") or tool.startswith("github.") or not is_nav(tool):
            continue
        urls = ff.urls_from_input(o.get("arguments") or {})
        if not urls:
            continue
        res = o.get("result") or {}
        sc_ = (res.get("structuredContent") or {}) if isinstance(res, dict) else {}
        failed = sc_.get("failed_results") if isinstance(sc_, dict) else None
        name = f"{server}:{tool}"
        if isinstance(failed, list) and (failed or sc_.get("results") is not None):
            bad = {}
            for f in failed:
                if isinstance(f, dict) and f.get("url"):
                    bad[f["url"]] = str(f.get("error") or "failed")
            for u in urls:
                if u in bad:
                    outcome, sc = classify_err(bad[u])
                    text = bad[u]
                else:
                    page = next((x.get("raw_content") or "" for x in sc_.get("results") or []
                                 if isinstance(x, dict) and x.get("url") == u), "")
                    outcome, sc = judge_fetch(False, page)
                    text = page
                rows.append(row("codex", entry, tid, name, u, outcome, sc, text, ts, panel, model, len(urls) > 1))
            continue
        err = (o.get("error") or {}).get("message", "") if isinstance(o.get("error"), dict) else ""
        body = text_of((res or {}).get("content") if isinstance(res, dict) else "")
        text = (err or body) if status == "failed" else body
        outcome, sc = judge_fetch(status == "failed", text)
        for u in urls:
            rows.append(row("codex", entry, tid, name, u, outcome, sc, text, ts, panel, model, len(urls) > 1))
    con.close()
    stats["codex:threads"] = len(th)
    return rows


# ---------------------------------------------------------------- Antigravity (protobuf steps)
def varint(b, i):
    shift = val = 0
    while i < len(b):
        x = b[i]
        i += 1
        val |= (x & 0x7F) << shift
        if not x & 0x80:
            return val, i
        shift += 7
        if shift > 70:
            break
    raise ValueError("varint")


def pb_strings(b, depth=0, out=None):
    out = out if out is not None else []
    i = 0
    try:
        while i < len(b):
            key, i = varint(b, i)
            wt = key & 7
            if wt == 0:
                _, i = varint(b, i)
            elif wt == 1:
                i += 8
            elif wt == 5:
                i += 4
            elif wt == 2:
                n, i = varint(b, i)
                chunk = b[i:i + n]
                i += n
                if not n:
                    continue
                if depth < 12:
                    sub = []
                    try:
                        pb_strings(chunk, depth + 1, sub)
                        if sub:
                            out.extend(sub)
                            continue
                    except ValueError:
                        pass
                try:
                    s = chunk.decode("utf-8")
                    if s.isprintable() or "\n" in s:
                        out.append(s)
                except UnicodeDecodeError:
                    pass
            else:
                raise ValueError("wiretype")
            if i > len(b):
                raise ValueError("overrun")
    except ValueError:
        if depth == 0:
            return out
        raise
    return out


def pb_epochs(b, depth=0, out=None):
    """Unix seconds (2025-06..2027-01) in a step's metadata blob; the smallest is the step's creation time.
    Checked T265: 391 read_url_content steps all fall in Aug 2026, as the conversation summaries say; the .db
    files' mtimes say September (something rewrote them), so mtime is not a date source."""
    out = out if out is not None else []
    i = 0
    try:
        while i < len(b):
            key, i = varint(b, i)
            wt = key & 7
            if wt == 0:
                v, i = varint(b, i)
                if 1_750_000_000 <= v <= 1_800_000_000:
                    out.append(v)
            elif wt == 1:
                i += 8
            elif wt == 5:
                i += 4
            elif wt == 2:
                n, i = varint(b, i)
                chunk = b[i:i + n]
                i += n
                if depth < 8 and n:
                    try:
                        pb_epochs(chunk, depth + 1, out)
                    except ValueError:
                        pass
            else:
                raise ValueError("wiretype")
    except ValueError:
        if depth == 0:
            return out
        raise
    return out


AGY_FETCH, AGY_MCP, AGY_CMD = 31, 38, 21
MCP_NAME = re.compile(r"^mcp_[a-z0-9_]+$")


def scan_agy(stats):
    rows = []
    for entry, (root, sumdb) in AGY.items():
        meta = {}
        if sumdb.exists():
            try:
                c = ro(sumdb)
                for cid, lm, ws in c.execute("select conversation_id, last_modified_time, workspace_uris "
                                             "from conversation_summaries"):
                    meta[cid] = (str(lm or "")[:19].replace(" ", "T") + "Z" if lm else None,
                                 bool(PANEL_RX.search(ws or "")))
                c.close()
            except sqlite3.Error as e:
                stats[f"{entry}:summaries_error:{type(e).__name__}"] += 1
        for db in sorted(root.glob("*.db")):
            cid = db.stem
            ts, panel = meta.get(cid, (dt.datetime.fromtimestamp(db.stat().st_mtime, dt.timezone.utc)
                                       .strftime("%Y-%m-%dT%H:%M:%SZ"), False))
            try:
                con = ro(db)
                steps = con.execute("select step_type, status, step_payload, error_details, metadata from steps "
                                    "where step_type in (?,?,?)", (AGY_FETCH, AGY_MCP, AGY_CMD)).fetchall()
                con.close()
            except sqlite3.Error as e:
                stats[f"{entry}:db_error:{type(e).__name__}"] += 1
                continue
            stats[f"{entry}:conversations"] += 1
            for stype, status, payload, ed, md in steps:
                stats[f"{entry}:step{stype}:status{status}"] += 1
                ep = pb_epochs(md or b"")
                step_ts = iso_ms(min(ep) * 1000) if ep else ts
                stats[f"{entry}:step_ts_from_{'metadata' if ep else 'summary'}"] += 1
                ss = pb_strings(payload or b"")
                err = " | ".join(dict.fromkeys(s for s in pb_strings(ed or b"") if len(s) > 3))
                is_error = bool(ed) or status == 7
                full = [s for s in ss if ff.URL_RE.fullmatch(s.strip())]
                longest = max((s for s in ss if not ff.URL_RE.fullmatch(s.strip())), key=len, default="")
                if stype == AGY_FETCH:
                    urls = full[:1] or ff.URL_RE.findall(err)[:1]
                    tool = "read_url_content"
                    outcome, sc = judge_fetch(is_error, err if is_error else longest, builtin=True)
                elif stype == AGY_MCP:
                    names = [s for s in ss if MCP_NAME.match(s)]
                    tool = names[0] if names else "mcp:?"
                    if not is_nav(tool.split("_", 2)[-1] if tool.startswith("mcp_") else tool):
                        continue
                    urls = full[:1]
                    outcome, sc = judge_fetch(is_error, err if is_error else longest)
                else:
                    cmds = [s for s in ss if ff.FETCH_VERB.search(s)]
                    urls = shell_urls(cmds[0]) if cmds else []
                    tool = "curl(run_command)"
                    if not urls:
                        continue
                    outcome, sc = judge_shell(is_error, err or longest, None, cmds[0])
                for u in urls:
                    rows.append(row("agy", entry, cid, tool, u, outcome, sc, err or longest, step_ts, panel))
    return rows


def freeze(rows, until, stats=None, name=""):
    """T271: keep only calls made at or before `until` (ISO UTC, e.g. 2026-11-16T07:30:00Z), the same cut as
    fetch_failures.py --until, so the counts stop growing between runs. Rows without a time are dropped and
    counted (they cannot be placed before the cut)."""
    if not until:
        return rows
    kept = [r for r in rows if r.get("ts") and r["ts"] <= until]
    if stats is not None:
        stats[f"{name}_frozen_out_after_until"] += sum(1 for r in rows if r.get("ts") and r["ts"] > until)
        stats[f"{name}_frozen_out_no_ts"] += sum(1 for r in rows if not r.get("ts"))
    return kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="opencode,codex,agy,mimo")
    ap.add_argument("--out", default=str(pathlib.Path(__file__).resolve().parent / "report-other"))
    ap.add_argument("--mimo-db", default="", help="path to MiMo Code's mimocode.db; MiMo is skipped without it")
    ap.add_argument("--until", default="", help="ISO UTC end time, e.g. 2026-11-16T07:30:00Z (T271 freeze)")
    a = ap.parse_args()
    global MIMO_DB
    if a.mimo_db:
        MIMO_DB = pathlib.Path(a.mimo_db)
    stats = collections.Counter()
    fns = {"opencode": scan_opencode, "codex": scan_codex, "agy": scan_agy, "mimo": scan_mimo}
    allrows = []
    out = pathlib.Path(a.out)
    for name in a.only.split(","):
        if name == "mimo" and MIMO_DB is None:
            print("[mimo] skipped: pass --mimo-db <path to mimocode.db>")
            continue
        try:
            rows = fns[name](stats)
        except (sqlite3.Error, OSError) as e:
            print(f"[{name}] skipped: no readable store on this machine ({type(e).__name__})")
            continue
        rows = [r for r in rows if r["host"] and not ff.is_local(r["host"])]
        rows = freeze(rows, a.until, stats, name)
        stats[f"{name}_multi_unclear"] = mark_multi(rows)
        allrows += rows
        ts = sorted(r["ts"] for r in rows if r["ts"])
        meta = {"store": name, "attempts": len(rows), "period": f"{ts[0][:10]} .. {ts[-1][:10]}" if ts else "-"}
        ff.report_v2(rows, str(out / name), meta, 40)
        oc = collections.Counter(r["outcome"] for r in rows)
        print(f"[{name}] attempts={len(rows)} period={meta['period']} outcomes={dict(oc.most_common())}")
        shapes = collections.defaultdict(collections.Counter)
        for r in rows:
            if r["outcome"] not in ("ok", "unrecorded"):
                shapes[(r["tool"], r["outcome"])][re.sub(r"\d", "N", r["detail"])[:90]] += 1
        for k, c in sorted(shapes.items(), key=lambda x: -sum(x[1].values()))[:14]:
            print(f"   {k} {sum(c.values())}: " + " || ".join(f"{n}x {s}" for s, n in c.most_common(2)))
    ff.report_v2(allrows, str(out / "all"), {"stores": a.only, "attempts": len(allrows)}, 60)
    (out / "stats.json").write_text(json.dumps(dict(sorted(stats.items())), indent=1), encoding="utf-8")
    print("stats keys:", len(stats), "->", out / "stats.json")


def selftest():
    cases = [
        ("opencode webfetch 403", classify_err("StatusCode: non 2xx status code (403 GET https://x.org/a)"), ("blocked", 403)),
        ("T266 opencode webfetch 401 = needs a key", classify_err("StatusCode: non 2xx status code (401 GET https://x.org/a)"),
         ("needs_auth", 401)),
        ("T266 shell counter printout", judge_shell(False, "HTTP 200 Just a moment: 0 cf-chl: 0"), ("ok", None)),
        ("agy 404 + stack with «permission»", classify_err(
            "Failed to fetch document content at https://x.org/a | failed to get URL https://x.org/a status code 404\n"
            "(2) attached stack trace\n  -- stack trace:\n  | handlers.(*ReadUrlContentHandler).Handle permissions"),
         ("not_found", 404)),
        ("keyword only in the URL", classify_err("Request to https://x.org/permissions/p timed out"), ("network", None)),
        ("codex cancel", classify_err("user cancelled MCP tool call"), ("tool_env", None)),
        ("mimo sibling cancel", classify_err("Tool call cancelled because an earlier tool call in this response failed."),
         ("tool_env", None)),
        ("transport", classify_err("Transport error (GET https://x.org/)"), ("network", None)),
        ("real deny rule stays permission", classify_err(
            "Permission denied for mcp(firecrawl/firecrawl_search). Matches user-configured deny rule."), ("permission", None)),
        ("302 is not a failure status", classify_err("StatusCode: non 2xx status code (302 GET https://x.org/)"),
         ("error_other", None)),
        ("localized PowerShell 503", judge_shell(True, "Invoke-WebRequest : ���: (503) ��.", 1,
                                                 "iwr https://x.org"), ("server_error", 503)),
        ("built-in page text with a status number", judge_fetch(False, 'x = {"status": 500}\n' * 3, builtin=True),
         ("ok", None)),
        ("MCP page text with a status number", judge_fetch(False, '{"statusCode": 403}'), ("blocked", 403)),
        ("challenge page via built-in", judge_fetch(False, "Just a moment... Enable JavaScript and cookies to continue",
                                                   builtin=True), ("challenge", None)),
    ]
    fz = freeze([{"ts": "2026-11-16T07:29:59Z"}, {"ts": "2026-11-16T07:30:00Z"}, {"ts": "2026-11-16T07:30:01Z"},
                 {"ts": None}], "2026-11-16T07:30:00Z")
    cases.append(("T271 --until keeps <= the cut, drops later and undated", (len(fz), fz[-1]["ts"]),
                  (2, "2026-11-16T07:30:00Z")))
    cases.append(("T271 no --until keeps everything", (len(freeze([{"ts": None}, {"ts": "2099"}], "")), None), (2, None)))
    bad = [(n, got, exp) for n, got, exp in cases if tuple(got) != exp]
    for n, got, exp in bad:
        print(f"FAIL {n}: got {got}, expected {exp}")
    print(f"VERDICT: {'OK' if not bad else 'FAIL'} {len(cases) - len(bad)}/{len(cases)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    main()
