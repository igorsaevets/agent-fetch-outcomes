# Agent fetch outcomes: what AI coding agents could not open

Data and scanners behind the article **[What AI coding agents could not open: 19,611 page fetches by six agents on one PC](https://page2ai.net/research/agent-fetch-outcomes/)** (2026-11-16).

Every call in which an AI agent on one Windows PC tried to open a web page, from 2026-05-09 to 2026-11-16 07:30 UTC, with the tool it used and what came back: content, a refusal by the site, a challenge page, HTTP 402, 404, a redirect, a network error, or an error inside the tool. Agents: Claude Code (CLI, the Code tab of Claude Desktop, headless runs), Claude Desktop chat through local MCP servers, Codex, OpenCode, MiMo Code and Antigravity.

## Contents

| Path | What it holds |
| --- | --- |
| [`article.md`](article.md) | the article, the same text as on page2ai.net |
| [`data/attempts.csv`](data/attempts.csv) | one row per call and URL (19,611 rows): date, agent, surface, tool, host, site type, URL, outcome, HTTP status, cleaned error text, whether the URL was in the conversation, which tool opened it later |
| [`data/sites_by_category.csv`](data/sites_by_category.csv) | one row per host and outcome group: failed calls, days, first and last date, the answers, the tools that failed and the tools that opened the host |
| [`data/summary.json`](data/summary.json) | the aggregates behind the article's tables and counts |
| [`data/README.md`](data/README.md) | the dataset card: columns, outcome classes, the publication filter, limits |
| [`scanners/fetch_failures.py`](scanners/fetch_failures.py) | scanner for Claude Code transcripts and Claude Desktop MCP logs |
| [`scanners/other_clis_t265.py`](scanners/other_clis_t265.py) | scanner for OpenCode, Codex, Antigravity and MiMo Code |

## Run the scanners on your own machine

```
cd scanners
python fetch_failures.py --selftest
python fetch_failures.py --out report
python other_clis_t265.py --selftest
python other_clis_t265.py --out report-other --mimo-db <path to mimocode.db>
```

Standard-library Python 3 (orjson is used when it is installed), tested with Python 3.14 on Windows 11. The scanners read the history files of the agents installed for the current user, read-only, and send nothing over the network. `--until <ISO time>` cuts the history at a moment (this dataset used `2026-11-16T07:30:00Z`); MiMo Code is scanned only when `--mimo-db` points at its database. Their output holds the URLs your agents opened: read it before you share it.

## What was removed before publication

The author's own sites, addresses on his private network and strings that were not URLs were removed (2,461 rows). URLs that could point at a person or an account (sign-in pages, consoles and dashboards, personal and social profiles, court records naming parties, search queries in the address, e-mail-like strings, ID numbers) were reduced to their host (1,307 URLs). Session and project names are replaced by keys. The exporter that applied the filter is not published, because its configuration names the author's private hosts; its rules are in [`data/README.md`](data/README.md).

## Limits

One person's work on one PC with one home connection in the US, so the sites are the ones that work needed. The agents chose the URLs and the author's own instructions set the order of fallback tools. The record does not say what a site saw (User-Agent, address), so the data cannot tell why a site refused. Details: the article's "Limitations" section and the dataset card.

## Disclosure

The author builds [Page2AI](https://page2ai.net/), a free tool that converts web pages to Markdown for language models. As a fetch tool it appears in this data only in two test calls (example.com) and is not compared with anything.

## License

- Data and article text: [CC BY 4.0](LICENSE).
- Code in `scanners/`: [MIT](LICENSE-CODE).

## Citation

Igor Saevets, "What AI coding agents could not open: 19,611 page fetches by six agents on one PC", page2ai.net, 2026, https://page2ai.net/research/agent-fetch-outcomes/. Machine-readable: [`CITATION.cff`](CITATION.cff).

Found an error in the data or the article? Please open an issue.
