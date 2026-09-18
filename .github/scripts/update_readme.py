#!/usr/bin/env python3
"""Regenerate the auto-updated sections of README.md.

Used by .github/workflows/update-readme.yml, which runs on every PR event
(opened / closed / reopened / ready for review).

Each managed section in README.md is delimited by HTML comment markers:

    <!-- RECENT-PRS:START -->
    ...generated content...
    <!-- RECENT-PRS:END -->

Environment variables:
    GITHUB_REPOSITORY  "owner/repo" (set automatically in Actions)
    GITHUB_TOKEN       token for the GitHub API (optional for local runs,
                       but rate limits are much lower without one)
    MAX_PRS            how many recent PRs to list (default: 10)

Only the Python standard library is used, so no dependencies are needed.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[2]  # repo root (script lives in .github/scripts/)
README = ROOT / "README.md"

REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
MAX_PRS = int(os.environ.get("MAX_PRS", "10"))


# --------------------------------------------------------------------------- #
# GitHub API helpers
# --------------------------------------------------------------------------- #
def api_get(path: str):
    """GET a GitHub API path and return the decoded JSON body."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "readme-auto-updater",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        print(f"::warning::GitHub API error {e.code} for {path}: {body}")
        raise SystemExit(f"GitHub API request failed: {path} (HTTP {e.code})")


def search_count(query: str) -> int:
    """Return the total_count for a GitHub issue/PR search query."""
    q = urllib.parse.quote(query, safe="")
    data = api_get(f"/search/issues?q={q}&per_page=1")
    return int(data.get("total_count", 0))


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #
def fmt_date(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return iso[:10]


def escape_cell(text: str) -> str:
    """Escape text so it can't break out of a markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def pr_status(pr: dict) -> str:
    if pr.get("draft") and pr.get("state") == "open":
        return "🚧 Draft"
    if pr.get("state") == "open":
        return "🟢 Open"
    if pr.get("merged_at"):
        return "🟣 Merged"
    return "🔴 Closed"


# --------------------------------------------------------------------------- #
# Section builders
# --------------------------------------------------------------------------- #
def build_stats_section() -> str:
    total = search_count(f"repo:{REPO} type:pr")
    open_count = search_count(f"repo:{REPO} type:pr state:open")
    merged = search_count(f"repo:{REPO} type:pr is:merged")
    closed_unmerged = max(total - open_count - merged, 0)
    try:
        info = api_get(f"/repos/{REPO}")
        stars = info.get("stargazers_count", "—")
        forks = info.get("forks_count", "—")
        issues = info.get("open_issues_count", "—")
    except SystemExit:
        stars = forks = issues = "—"

    return (
        "| 📊 Metric | Count |\n"
        "|---|---|\n"
        f"| Total pull requests | **{total}** |\n"
        f"| 🟢 Open | {open_count} |\n"
        f"| 🟣 Merged | {merged} |\n"
        f"| 🔴 Closed (unmerged) | {closed_unmerged} |\n"
        f"| ⭐ Stars | {stars} |\n"
        f"| 🍴 Forks | {forks} |\n"
        f"| 🐞 Open issues | {issues} |\n"
    )


def build_recent_prs_section() -> str:
    prs = api_get(
        f"/repos/{REPO}/pulls?state=all&sort=updated&direction=desc&per_page={MAX_PRS}"
    )
    if not prs:
        return (
            "_No pull requests yet — be the first to open one! 🎉_\n\n"
            f"[Open a pull request](https://github.com/{REPO}/compare)\n"
        )
    lines = [
        "| PR | Title | Author | Status | Created | Last updated |",
        "|---|---|---|---|---|---|",
    ]
    for pr in prs:
        number = pr.get("number")
        title = escape_cell(pr.get("title") or "(no title)")
        url = pr.get("html_url", "")
        user = (pr.get("user") or {}).get("login", "ghost")
        lines.append(
            f"| [#{number}]({url}) | [{title}]({url}) "
            f"| [@{user}](https://github.com/{user}) "
            f"| {pr_status(pr)} "
            f"| {fmt_date(pr.get('created_at'))} "
            f"| {fmt_date(pr.get('updated_at'))} |"
        )
    lines.append("")
    noun = "PR" if len(prs) == 1 else "PRs"
    lines.append(f"_Showing the {len(prs)} most recently updated {noun}. "
                 f"[View all](https://github.com/{REPO}/pulls)_")
    return "\n".join(lines) + "\n"


def build_contributors_section() -> str:
    contributors = api_get(f"/repos/{REPO}/contributors?per_page=30")
    if not contributors:
        return "_No contributors yet — contributions welcome! 🙌_\n"
    avatars = []
    bullets = []
    for c in contributors:
        login = c.get("login", "ghost")
        commits = c.get("contributions", 0)
        avatars.append(
            f'  <a href="https://github.com/{login}">'
            f'<img src="https://github.com/{login}.png?size=100" '
            f'width="60" height="60" alt="{login}" /></a>'
        )
        bullets.append(
            f"- [@{login}](https://github.com/{login}) — {commits} contribution"
            f"{'s' if commits != 1 else ''}"
        )
    return (
        '<p align="left">\n' + "\n".join(avatars) + "\n</p>\n\n" + "\n".join(bullets) + "\n"
    )


def build_last_updated_section() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"_Last updated: **{now}** — this README refreshes itself automatically "
        f"on every pull request via the "
        f"[Auto-update README](https://github.com/{REPO}/actions/workflows/update-readme.yml) "
        f"workflow._\n"
    )


# --------------------------------------------------------------------------- #
# Marker replacement
# --------------------------------------------------------------------------- #
def replace_section(content: str, key: str, body: str) -> str:
    start = f"<!-- {key}:START -->"
    end = f"<!-- {key}:END -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    replacement = f"{start}\n{body.rstrip()}\n{end}"
    if not pattern.search(content):
        print(f"::warning::Markers for '{key}' not found in README.md — skipping.")
        return content
    return pattern.sub(replacement, content, count=1)


def main() -> None:
    if not REPO or "/" not in REPO:
        raise SystemExit("GITHUB_REPOSITORY env var must be set to 'owner/repo'.")
    if not README.exists():
        raise SystemExit(f"README not found at {README}")
    if not TOKEN:
        print("::warning::No GITHUB_TOKEN set — API rate limits will be very low.")

    print(f"Updating {README} for repo {REPO} ...")
    content = README.read_text(encoding="utf-8")

    sections = {
        "PR-STATS": build_stats_section(),
        "RECENT-PRS": build_recent_prs_section(),
        "CONTRIBUTORS": build_contributors_section(),
        "LAST-UPDATED": build_last_updated_section(),
    }
    for key, body in sections.items():
        content = replace_section(content, key, body)
        print(f"  ✓ {key}")

    if content != README.read_text(encoding="utf-8"):
        README.write_text(content, encoding="utf-8")
        print("README.md updated.")
    else:
        print("README.md already up to date — no changes.")


if __name__ == "__main__":
    main()
