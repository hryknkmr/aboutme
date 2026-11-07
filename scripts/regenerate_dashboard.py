#!/usr/bin/env python3
"""Regenerate docs/index.html and docs/assets/*-card.svg from GitHub PR activity.

Usage:
    python3 scripts/regenerate_dashboard.py --since 2026-06-29 [--date 2026-11-07]

Requires an authenticated `gh` CLI. Only owners in ALLOWED_OWNERS are read.
PR bodies are used only to extract vocabulary terms; only titles and links of
PRs from allowed owners are published.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import itertools
import json
import math
import re
import subprocess
import unicodedata
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "docs" / "index.html"
ASSETS = ROOT / "docs" / "assets"

ALLOWED_OWNERS = ["hryknkmr", "hrykn"]
EXCLUDED_REPOS = {"aboutme"}
# CI-gate-only PRs (opened just to run CI on a local squash, never merged by design).
GATE_ONLY = re.compile(r"マージしない|do not merge", re.I)

# Items whose title mentions these are kept in the stats but not listed by title.
SUPPRESSED_TITLE_TERMS = [
    r"chrome(?!-ai)", r"notion", r"slack", r"mabl", r"claude", r"codex", r"openai",
    r"gemini", r"pocake", r"note\.com", r"contabo", r"stalwart",
]
# Security-related titles are never listed (could advertise an unfixed weakness).
SENSITIVE_TITLE = re.compile(
    r"secur|vulnerab|脆弱|\bcve\b|secret|credential|token|password|passwd|auth|exploit|"
    r"\bxss\b|csrf|injection|leak|漏洩|権限|秘匿|個人情報|\bpii\b|\.(?:work|com|net|jp|io)\b|@|"
    # network / trust boundary
    r"host|origin|alias|receiver|endpoint|\bport\b|network|\bcors\b|\bcsp\b|cookie|session|"
    r"local|remote|domain|\burls?\b|\bip\b|proxy|"
    # permission / defence wording (describing a guard can reveal its limits)
    r"permission|allow|deny|denied|refus|reject|block|guard|sandbox|trust|spoof|imitat|bypass|"
    r"sanitiz|escap|redact|mask|hide|hidden|expos|sensitive|restrict|limit|covers? only|name check|"
    r"private|public|privacy|"
    r"ホスト|許可|拒否|制限|遮断|ガード|隠|マスク|公開|信頼|偽装|回避|露出|検査|"
    # identity / crypto / attack vocabulary
    r"oauth|\bjwt\b|\brbac\b|\bacl\b|\bsso\b|\bsaml\b|oidc|\btls\b|\bssl\b|\bssh\b|\bgpg\b|"
    r"encrypt|decrypt|crypt|cipher|hash|signature|signing|certificat|\bkeys?\b|login|logout|sign[- ]?in|"
    r"account|user ?id|rate[- ]?limit|throttl|attack|threat|malicious|harden|defen[cs]|boundar|isolat|"
    r"firewall|\bwaf\b|audit|compliance|\bgdpr\b|\bsbom\b|dependabot|"
    r"認証|認可|暗号|証明書|署名|鍵|攻撃|防御|境界|脅威|不正|監査|ログイン|アカウント|分離|隔離|"
    # attack classes
    r"\brce\b|\bsqli?\b|\bxxe\b|\bssrf\b|\bidor\b|\bdos\b|\bddos\b|traversal|pollution|"
    r"(?:code|command) execution|arbitrary (?:file|code|command)|deserializ|overflow|"
    r"clickjack|phishing|privilege|escalat|takeover|hijack|tamper|poison|"
    r"open redirect|request smuggling|race condition|\btoctou\b|\blfi\b|\bssti\b|\bredos\b|zip slip|"
    r"実行可能|任意(?:の)?(?:コード|コマンド|ファイル)|コード実行|コマンド実行|"
    r"トラバーサル|オーバーフロー|プロトタイプ汚染|デシリアライゼーション|"
    r"オープンリダイレクト|リクエストスマグリング|競合状態|乗っ取|改ざん|昇格|注入",
    re.I,
)
# A private title is listed only if it has none of: digits (PR/issue/ADR/ticket
# numbers, IPs, phone numbers), reference/path/address punctuation, or host words.
PRIVATE_TITLE_REJECT = re.compile(r"[0-9#!@/\\:|<>{}\[\]=~$%&*^`]|\.\w|localhost|https?|www", re.I)


def sensitive_names() -> set[str]:
    """Names that must never appear in a listed title: every repository of the
    allowlisted owners and every organization the authenticated user belongs to."""
    names = set(ALLOWED_OWNERS)
    for owner in ALLOWED_OWNERS:
        for r in gh_json(["repo", "list", owner, "--limit", "1000", "--json", "name"]):
            names.add(r["name"])
    for org in gh_json(["api", "user/orgs", "--paginate"]):
        names.add(org["login"])
    out = set()
    for n in names:
        n = unicodedata.normalize("NFKC", n).casefold()
        out.add(n)
        out.update(p for p in re.split(r"[-_.]", n) if len(p) >= 5 and p not in GENERIC_NAME_PARTS)
    return out


GENERIC_NAME_PARTS = {"tests", "testing", "sandbox", "regression", "server", "frontend", "backend",
                      "guardrails", "mapper", "check", "workbench", "playwright", "scribe"}
FOOTER = (
    '<div class="footer">Generated from allowlisted owners only. Statistics include private repositories; '
    "private items are listed by title only, without repository names, links or cross-references, and "
    "security-related titles are omitted. Vendor-specific product names are suppressed; general engineering "
    "terms such as SSOT, Playwright, a11y, WCAG, and GitHub Actions are retained.</div>"
)


def b(word: str) -> str:
    """Boundary that also works next to Japanese text."""
    return rf"(?<![A-Za-z0-9_]){word}(?![A-Za-z0-9_])"


STACK = {
    "ESLint": b("eslint"),
    "npm": b("npm"),
    "pnpm": b("pnpm"),
    "Biome": b("biome"),
    "Playwright": b("playwright"),
    "a11y": b("a11y") + r"|accessib|アクセシビリティ",
    "axe": b("axe(?:-core)?"),
    "DOM": b("dom"),
    "Docker": b("docker"),
    "GitHub Actions": r"github actions|" + b("workflows?") + r"|\.github/workflows",
    "SSOT": b("ssot") + r"|single source of truth|正本",
    "KPI": b("kpi"),
    "TypeScript": b("typescript") + "|" + b("ts"),
    "Node.js": r"node\.js|" + b("node"),
    "Chromium": b("chromium"),
    "WebExtension": r"web ?extension|manifest v3|" + b("mv3") + r"|content scripts?|service worker",
    "Markdown": b("markdown"),
    "Gherkin": b("gherkin"),
    "ADR": b("adr"),
    "E2E": b("e2e"),
    "git hooks": r"pre-(?:commit|push)|git hooks?|" + b("hooks?"),
    "Shell": b("bash|zsh|shell"),
    "Python": b("python"),
    "WCAG": b("wcag"),
    "MCP": b("mcp"),
}

SIGNALS = {
    "Audit": b("audit") + r"|監査",
    "Flaky": b("flak(?:y|iness)") + r"|揺れ|不安定",
    "Coverage": b("coverage") + r"|カバレッジ",
    "Failure": b("fail(?:s|ed|ure|ing)?") + r"|失敗",
    "Regression": b("regressions?") + r"|退行|デグレ",
    "Bug": b("bugs?") + r"|バグ",
    "Timeout": b("time ?outs?") + r"|タイムアウト|時間切れ",
    "False Positive": r"false positive|誤検知|誤判定",
    "False Negative": r"false negative|見逃し",
    "Hardening": b("harden(?:ing|ed)?") + r"|堅牢",
    "Security": b("security|vulnerabilit(?:y|ies)") + r"|脆弱性",
    "Privacy": b("pii|redact(?:ed|ion)?|mask(?:ed|ing)?") + r"|個人情報|秘匿|マスキング",
    "Race": b("race(?: condition)?") + r"|競合",
}

THEMES = {
    "developer tooling": r"tool|lint|cli|script|guard|hook|ツール|ガード",
    "documentation": b("docs?") + r"|readme|adr|document|ドキュメント|文書",
    "ci/cd": b("ci") + r"|workflow|github actions|pipeline",
    "product flows": r"flow|journey|session|recording|replay|フロー|導線",
    "quality assurance": r"\bqa\b|quality|review|verify|検証|品質|レビュー",
    "automation and metrics": r"automat|metric|kpi|ledger|measure|計測|集計|自動",
    "e2e testing": b("e2e") + r"|end-to-end|playwright|spec",
    "selectors and dom": b("dom") + r"|selector|locator|セレクタ",
    "accessibility": r"a11y|accessib|wcag|axe|アクセシビリティ",
    "source-of-truth alignment": r"ssot|source of truth|正本|in line|align|揃え|そろえ",
    "privacy and security": r"secur|privacy|pii|redact|mask|脆弱性|個人情報|秘匿",
    "browser extension": r"extension|content script|service worker|拡張",
}

SEARCH_LIMIT = 1000
TOP_N = 10
EDGES_N = 18


def compile_all(d: dict[str, str]) -> dict[str, re.Pattern]:
    return {k: re.compile(v, re.I) for k, v in d.items()}


def gh_json(args: list[str]):
    out = subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def fetch(since: str) -> list[dict]:
    items = []
    for owner in ALLOWED_OWNERS:
        got = gh_json([
            "search", "prs", "--owner", owner, "--created", f">={since}", "--limit", str(SEARCH_LIMIT),
            "--json", "repository,number,title,createdAt,state,url,body",
        ])
        if len(got) >= SEARCH_LIMIT:
            raise SystemExit(f"{owner}: hit the {SEARCH_LIMIT}-result search cap; use a later --since")
        items += got
    items = [
        x for x in items
        if x["repository"]["name"] not in EXCLUDED_REPOS
        and x["state"] != "closed"
        and not GATE_ONLY.search(x["title"])
    ]
    visibility: dict[str, str] = {}
    for x in items:
        full = x["repository"]["nameWithOwner"]
        if full not in visibility:
            try:
                visibility[full] = gh_json(["api", f"repos/{full}"]).get("visibility", "")
            except subprocess.CalledProcessError:
                visibility[full] = ""
        # Fail closed: anything not confirmed public is treated as private.
        x["public"] = visibility[full] == "public"
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items


def graph(docs: list[set[str]], weights: dict[str, float], idf: dict[str, float] | None):
    top = sorted(weights, key=lambda k: (-weights[k], k))[:TOP_N]
    nodes = []
    for k in top:
        node = {"id": k, "weight": round(weights[k], 3)}
        if idf is not None:
            node["document_frequency"] = sum(k in d for d in docs)
            node["idf"] = round(idf[k], 4)
        nodes.append(node)
    co = Counter()
    for d in docs:
        for a, c in itertools.combinations(sorted(set(d) & set(top)), 2):
            co[(a, c)] += 1
    edges = []
    for (a, c), n in co.items():
        w = n * (idf[a] + idf[c]) / 2 if idf is not None else n
        edges.append({"source": a, "target": c, "weight": round(w, 3)})
    edges.sort(key=lambda e: (-e["weight"], e["source"], e["target"]))
    return top, {"nodes": nodes, "edges": edges[:EDGES_N]}


def card_svg(title: str, subtitle: str, rows: list[tuple[str, float]]) -> str:
    font = "Avenir Next, Helvetica Neue, Arial, sans-serif"
    mono = "SFMono-Regular, Menlo, monospace"
    mx = max((v for _, v in rows), default=1) or 1
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="760" height="432" viewBox="0 0 760 432" role="img" aria-label="{title}">',
        "<defs>",
        '<linearGradient id="bar" x1="0%" y1="0%" x2="100%" y2="0%">',
        '<stop offset="0%" stop-color="#0f766e"/>',
        '<stop offset="100%" stop-color="#f97316"/>',
        "</linearGradient>",
        "</defs>",
        '<rect width="760" height="432" rx="28" fill="#fffdf8" stroke="#eadfca"/>',
        f'<text x="32" y="38" font-family="{font}" font-size="24" font-weight="700" fill="#111827">{title}</text>',
        f'<text x="32" y="62" font-family="{font}" font-size="13" fill="#6b7280">{subtitle}</text>',
    ]
    for i, (label, v) in enumerate(rows):
        y = 98 + 58 * i
        out += [
            f'<text x="32" y="{y}" font-family="{font}" font-size="16" font-weight="600" fill="#1f2937">{html.escape(label)}</text>',
            f'<rect x="250" y="{y - 16}" width="420" height="14" rx="7" fill="#efe8da"/>',
            f'<rect x="250" y="{y - 16}" width="{420 * v / mx:.1f}" height="14" rx="7" fill="url(#bar)"/>',
            f'<text x="690" y="{y - 2}" text-anchor="end" font-family="{mono}" font-size="13" fill="#6b7280">{v:.2f}</text>',
        ]
    out.append("</svg>")
    return "\n".join(out) + "\n"


def sub_once(pattern: str, repl: str, text: str) -> str:
    new, n = re.subn(pattern, lambda _m: repl, text, count=1, flags=re.S)
    if n != 1:
        raise SystemExit(f"template anchor not found: {pattern}")
    return new


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, type=lambda v: dt.date.fromisoformat(v).isoformat(),
                    help="YYYY-MM-DD, PRs created on/after")
    ap.add_argument("--date", type=lambda v: dt.date.fromisoformat(v).isoformat(),
                    default=dt.date.today().isoformat())
    ap.add_argument("--entries", type=int, default=8)
    args = ap.parse_args()

    items = fetch(args.since)
    if not items:
        raise SystemExit("no items")
    stack_re, sig_re, theme_re = compile_all(STACK), compile_all(SIGNALS), compile_all(THEMES)
    suppressed = re.compile("|".join(SUPPRESSED_TITLE_TERMS), re.I)

    n = len(items)
    tf, stack_docs, sig_docs, theme_docs = Counter(), [], [], []
    for x in items:
        text = f"{x['title']}\n{x.get('body') or ''}"
        found = set()
        for k, r in stack_re.items():
            c = len(r.findall(text))
            if c:
                tf[k] += c
                found.add(k)
        stack_docs.append(found)
        sig_docs.append({k for k, r in sig_re.items() if r.search(text)})
        theme_docs.append({k for k, r in theme_re.items() if r.search(text)})

    df = Counter(k for d in stack_docs for k in d)
    idf = {k: math.log((1 + n) / (1 + df[k])) + 1 for k in df}
    stack_w = {k: tf[k] * idf[k] for k in df}
    sig_w = Counter(k for d in sig_docs for k in d)
    theme_w = Counter(k for d in theme_docs for k in d)

    stack_top, g_stack = graph(stack_docs, stack_w, idf)
    sig_top, g_sig = graph(sig_docs, dict(sig_w), None)
    theme_top, g_theme = graph(theme_docs, dict(theme_w), None)
    data = {"stack": g_stack, "signal": g_sig, "theme": g_theme}

    chips = "".join(f'<span class="chip">{html.escape(k)}</span>' for k in stack_top[:6])
    warm = "".join(f'<span class="chip chip-warm">{html.escape(k)}</span>' for k in sig_top[:6])
    themes = "".join(
        f'<div class="mini-row"><span>{html.escape(k)}</span><b>{theme_w[k]}</b></div>' for k in theme_top[:6]
    )
    rank = {k: i for i, k in enumerate(sorted(stack_w, key=lambda k: -stack_w[k]))}
    sig_rank = {k: i for i, k in enumerate(sorted(sig_w, key=lambda k: -sig_w[k]))}
    entries = []
    names = sensitive_names()
    for x, st, sg in zip(items, stack_docs, sig_docs):
        title = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", x["title"])).strip()
        low = title.casefold()
        if suppressed.search(title) or SENSITIVE_TITLE.search(title) or any(n in low for n in names):
            continue
        if x["public"]:
            meta = f'<div class="entry-meta">stack: {html.escape(", ".join(sorted(st, key=rank.get)) or "-")}</div>'
            meta += f'<div class="entry-meta">signals: {html.escape(", ".join(sorted(sg, key=sig_rank.get)) or "-")}</div>'
            entries.append(
                f'<a class="entry" href="{html.escape(x["url"])}"><div class="entry-title">{html.escape(title)}</div>{meta}</a>'
            )
        else:
            # Private repo: sanitized title only. Fail closed: titles carrying any
            # reference / identifier / address-like token are omitted, not rewritten.
            if PRIVATE_TITLE_REJECT.search(title):
                continue
            entries.append(f'<div class="entry"><div class="entry-title">{html.escape(title)}</div></div>')
        if len(entries) >= args.entries:
            break

    page = INDEX.read_text()
    page = sub_once(r'<div class="footer">.*?</div>', FOOTER, page)
    page = sub_once(r'<div class="chips"><span class="chip">.*?</div>', f'<div class="chips">{chips}</div>', page)
    page = sub_once(r'<div class="chips"><span class="chip chip-warm">.*?</div>', f'<div class="chips">{warm}</div>', page)
    page = sub_once(r"<small>Updated</small><strong>.*?</strong>", f"<small>Updated</small><strong>{args.date}</strong>", page)
    page = sub_once(r"<small>Allowed owners</small><strong>.*?</strong>", f"<small>Allowed owners</small><strong>{len(ALLOWED_OWNERS)}</strong>", page)
    page = sub_once(r"<small>Items analyzed</small><strong>.*?</strong>", f"<small>Items analyzed</small><strong>{n}</strong>", page)
    for anchor, body in [
        ("Top Themes</h2>", themes),
        ("Recent Public-Safe Activity</h2>", f'<div class="entry-list">{"".join(entries)}</div>'),
    ]:
        page, k = re.subn(rf"({re.escape(anchor)}\n\s*)[^\n]*", lambda m, body=body: m.group(1) + body, page, count=1)
        if k != 1:
            raise SystemExit(f"template anchor not found: {anchor}")
    graph_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    page = sub_once(r'(<script id="graph-data" type="application/json">).*?(</script>)',
                    f'<script id="graph-data" type="application/json">{graph_json}</script>', page)
    INDEX.write_text(page)

    (ASSETS / "stack-card.svg").write_text(
        card_svg("Current Stack", "tf-idf weighted stack terms", [(k, stack_w[k]) for k in stack_top[:6]]))
    (ASSETS / "signal-card.svg").write_text(
        card_svg("Quality Signals", "frequent quality / defect language", [(k, float(sig_w[k])) for k in sig_top[:6]]))

    print(f"items={n} stack={stack_top[:6]} signals={sig_top[:6]} themes={theme_top[:6]} entries={len(entries)}")


if __name__ == "__main__":
    main()
