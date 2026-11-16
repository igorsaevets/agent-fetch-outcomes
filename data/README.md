# Agent fetch outcomes: 19,611 page fetches by six AI agents on one PC (2026)

Every call in which an AI agent on one Windows PC tried to open a web page, from 2026-05-09 to 2026-11-16 07:30 UTC, with its tool and its outcome. Agents: Claude Code (CLI, the Code tab of Claude Desktop, headless runs), Claude Desktop chat (its MCP servers only), Codex, OpenCode, MiMo Code, Antigravity. Companion data for the article "What AI coding agents could not open" (page2ai.net, 2026).

Article: https://page2ai.net/research/agent-fetch-outcomes/ · Repository: https://github.com/igorsaevets/agent-fetch-outcomes

## Files

| file | rows | what |
|---|---|---|
| `attempts.csv` | 19,611 | one row per tool call and URL |
| `sites_by_category.csv` | one per host and outcome group | failures per host, with evidence columns |
| `summary.json` | - | the aggregates behind the article's tables and counts (block `t272` holds the numbers added after review) |

## `attempts.csv`

| column | meaning |
|---|---|
| `date` | UTC day of the call |
| `agent` | `claude-code`, `claude-desktop-chat`, `codex`, `opencode`, `mimo-code`, `antigravity` |
| `surface` | where the agent ran: `cli`, `desktop-code-tab`, `sdk-headless`, `desktop-chat-mcp-log`, `codex-exec`, `codex-app`, `codex-cli`, `codex-subagent`, `agy-cli`, `agy-ide`, `opencode`, `mimo` |
| `subagent` | the call came from a Claude Code sub-agent |
| `automated_review` | the session was an unattended review run started by a script (non-Claude agents only; empty for Claude) |
| `model` | the model recorded by the agent (non-Claude agents only) |
| `session_key`, `project_key` | stable keys replacing session ids and project folder names |
| `seq` | order of the call within its session |
| `tool` | the tool as the agent names it (`WebFetch`, `webfetch`, `jina-mcp-server:read_url`, `Bash`, ...) |
| `tool_family` | `built-in fetch`, `remote reader service`, `local browser or scraper`, `shell HTTP client`, `other MCP tool` |
| `host` | host name without `www.` |
| `site_type` | a rule-based guess from the host name: government, legal, academic, AI vendor, documentation, code and packages, store or directory, social or forum, news and media, archive, search or reader proxy, other |
| `url` | scheme, host and path; no query string or fragment; at most 200 characters; `https://host/` when reduced by the filter |
| `url_redacted` | the filter rule that reduced the URL to its host, if any |
| `outcome` | the scanner's class (`ok`, `blocked`, `challenge`, `js_wall`, `http_402`, `not_found`, `redirect`, `login_wall`, `needs_auth`, `network`, `server_error`, `tool_policy`, `service_refused`, `tool_env`, `permission`, `usage`, `error_other`, `script_error`, `http_other`, `http_error_unknown`, `multi_unclear`, `unrecorded`) |
| `outcome_group` | the group used in the article (opened, refused by the site, HTTP 402, not found, redirect not followed, refused by the agent's own policy, refused by a fetch service, login or key needed, network or server error, tool-side error, other HTTP error, unclear, not recorded) |
| `http_status` | the status the tool reported, when it reported one |
| `url_in_context` | Claude Code only: `seen` if the URL appeared in a user message or tool result earlier in the same transcript, `constructed` if not. URLs are compared without scheme, `www.`, query string and trailing slash, as recorded before the filter. The check does not see the system prompt, project instructions or relative links, and a URL the model wrote counts as seen once a tool has echoed it, so errors go both ways |
| `rescued_by` | for a failed call: the first other tool that opened the same URL (exact string, as recorded before the filter) later in the same session |
| `detail` | the tool's error text, shortened, with URLs, paths, numbers and secret-shaped strings masked |
| `multi_url_call` | the call asked for several URLs |
| `low_confidence` | the URL came from a shell command, which may mention a URL without requesting it |

## `sites_by_category.csv`

One row per host and outcome group (failures only): `category`, `host`, `site_type`, `failed_attempts`, `days` (distinct days with that failure), `first_failed`, `last_failed`, `kinds` (outcome and status counts), `tools_failed`, `agents_failed`, `attempts_on_host` and `opened_on_host` (all calls to the host), `tools_opened`, `example_url` (the latest failed URL, after the filter). No row is hidden for having few failures. `attempts_on_host` also counts tool-side errors, unclear answers and calls with no recorded outcome, which this file does not list, so it can exceed the sum of `failed_attempts`; the tool and answer columns list at most six entries.

## How it was built

Two scanners (in `scanners/` of the repository) read the agents' local histories: `fetch_failures.py` (Claude Code JSONL transcripts, Claude Desktop MCP logs) and `other_clis_t265.py` (OpenCode and MiMo Code SQLite, Codex thread history and rollouts, Antigravity conversation databases). Both key rows by tool call id, read the tool's structured status before any text, and cut the history at `--until 2026-11-16T07:30:00Z`. An exporter then applied the publication filter and computed `url_in_context` and `rescued_by`.

## The publication filter

Rules, in order; the first match decides. Removed rows are in no file; reduced rows keep everything except the URL path.

- removed: `ip_address` (a literal IP as host), `not_a_url` (strings taken from code, such as `${path}`), `private_network` (local names, private and tailnet addresses), `own_site` (the author's own domains and deployments), `private_infrastructure`, `private_repository`, `secret_like` (tokens, credentials in URLs), `robots_file` (requests for `/robots.txt` files themselves)
- reduced to host: `login_or_capability` (sign-in pages, dashboards, consoles, account and settings pages, share links), `person_or_social_profile` (social networks, personal profile and author pages, private sellers' listings; personal blogs and articles are kept), `court_record` (court dockets, filings and case-law pages whose address names the parties; statutes and regulations are kept), `search_query` (search services that put the query into the address), `email_like`, `ip_in_path` (an IP address other than a public DNS resolver), `id_number` (case and receipt numbers, personal ID numbers, phone numbers), `author_business` (pages naming the author's other business)

Pages about the author's own public projects on other sites (a store listing, package registries, directories) are kept.

Counts per rule are in `summary.json` (`filter`) and in the article. The deny list naming the author's hosts is not published.

## Limits

One person's work with tools started on one PC with one home connection in the US (reader services fetch from their own servers); the agents chose the URLs and the author's own instructions set the order in which they fell back from one tool to another; "opened" means the tool returned content (WebFetch returns a summary and caches pages for 15 minutes); the data does not record the User-Agent, address or TLS fingerprint of a call; classification is heuristic; Codex's hosted `web_search` records no outcome; the Claude Desktop chat's built-in fetch, claude.ai, Cowork and cloud sessions are not included.

## License and citation

Data: CC BY 4.0. Code: MIT. Cite as: Igor Saevets, "What AI coding agents could not open: 19,611 page fetches by six agents on one PC", page2ai.net, 2026, https://page2ai.net/research/agent-fetch-outcomes/. Data and scanners: https://github.com/igorsaevets/agent-fetch-outcomes.
