#!/usr/bin/env python3
"""
Ad-block rule merger with Trie-based domain deduplication.
Fetches multiple rule lists, normalises to Loon format,
removes redundant sub-domains via a suffix trie, then writes
a single output file.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import aiohttp
import yaml

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Trie
# ──────────────────────────────────────────────
@dataclass
class TrieNode:
    children: dict[str, "TrieNode"] = field(default_factory=dict)
    is_suffix: bool = False   # DOMAIN-SUFFIX node (catches all sub-domains)
    is_exact:  bool = False   # DOMAIN node


class DomainTrie:
    """
    Reversed-label trie for domain rules.

    Insertion semantics
    -------------------
    DOMAIN-SUFFIX, example.com
        → path ["com", "example"] → mark is_suffix=True
        → any future DOMAIN or DOMAIN-SUFFIX that starts with this
          path is redundant and discarded.

    DOMAIN, ads.example.com
        → path ["com", "example", "ads"]
        → if any ancestor node has is_suffix=True → redundant, skip.
        → otherwise mark is_exact=True on the leaf.

    Pruning on DOMAIN-SUFFIX insertion
        → when marking a node as is_suffix, delete all its children
          (they are now subsumed) and clear is_exact on that node.
    """

    def __init__(self) -> None:
        self._root = TrieNode()

    # ------------------------------------------------------------------
    def insert_suffix(self, domain: str) -> bool:
        """
        Insert DOMAIN-SUFFIX rule.
        Returns True if inserted (not redundant), False if discarded.
        """
        labels = _reversed_labels(domain)
        if not labels:
            return False
        node = self._root
        for label in labels:
            # If any ancestor is already a suffix node → redundant
            if node.is_suffix:
                return False
            node = node.children.setdefault(label, TrieNode())
        # Reached the target node
        if node.is_suffix:
            return False   # exact duplicate
        # Mark and prune all children (they are now subsumed)
        node.is_suffix = True
        node.is_exact  = False
        node.children.clear()
        return True

    # ------------------------------------------------------------------
    def insert_exact(self, domain: str) -> bool:
        """
        Insert DOMAIN rule.
        Returns True if inserted (not redundant), False if discarded.
        """
        labels = _reversed_labels(domain)
        if not labels:
            return False
        node = self._root
        for label in labels:
            if node.is_suffix:
                return False   # covered by ancestor suffix rule
            node = node.children.setdefault(label, TrieNode())
        if node.is_suffix or node.is_exact:
            return False
        node.is_exact = True
        return True

    # ------------------------------------------------------------------
    def emit(self) -> Iterator[tuple[str, str]]:
        """Yield (rule_type, domain) for every surviving rule."""
        yield from self._walk(self._root, [])

    def _walk(self, node: TrieNode, path: list[str]) -> Iterator[tuple[str, str]]:
        if node.is_suffix:
            yield ("DOMAIN-SUFFIX", _join_labels(path))
            return   # children pruned at insert time
        if node.is_exact:
            yield ("DOMAIN", _join_labels(path))
        for label, child in node.children.items():
            yield from self._walk(child, [label] + path)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
_VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9\u4e00-\u9fff]"          # IDN support (basic)
    r"(?:[a-zA-Z0-9\u4e00-\u9fff\-]{0,61}"
    r"[a-zA-Z0-9\u4e00-\u9fff])?\.)+"
    r"[a-zA-Z\u4e00-\u9fff]{2,}$"
)


def _is_valid_domain(d: str) -> bool:
    return bool(_VALID_DOMAIN_RE.match(d))


def _reversed_labels(domain: str) -> list[str]:
    parts = domain.lower().strip(".").split(".")
    return list(reversed(parts)) if all(parts) else []


def _join_labels(reversed_path: list[str]) -> str:
    return ".".join(reversed_path)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ──────────────────────────────────────────────
# Rule parsing / normalisation
# ──────────────────────────────────────────────
@dataclass
class Rule:
    kind: str    # DOMAIN | DOMAIN-SUFFIX | IP-CIDR | IP-CIDR6 | OTHER
    value: str

    def __hash__(self):
        return hash((self.kind, self.value))

    def __eq__(self, other):
        return (self.kind, self.value) == (other.kind, other.value)


# Mapping of alias prefixes → canonical Loon prefixes
_PREFIX_MAP: dict[str, str] = {
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "DOMAIN":        "DOMAIN",
    "HOST-SUFFIX":   "DOMAIN-SUFFIX",
    "HOST-KEYWORD":  "DOMAIN-KEYWORD",
    "HOST":          "DOMAIN",
    "IP-CIDR6":      "IP-CIDR6",
    "IP-CIDR":       "IP-CIDR",
    "IP6-CIDR":      "IP-CIDR6",
}

# Lines to skip entirely
_SKIP_RE = re.compile(
    r"^(?:#|!|\[|@@|/|\s*$)"   # comments, [section], ABP allowlist, regex
)

# ABP-style ||domain.com^  →  DOMAIN-SUFFIX
_ABP_BLOCK_RE = re.compile(r"^\|\|([^/^*\s]+)\^?$")

# QX leading dot:  .example.com  →  DOMAIN-SUFFIX,example.com
_QX_DOT_RE = re.compile(r"^\.([\w.\-]+)$")


def parse_line(raw: str) -> Optional[Rule]:
    line = raw.strip()
    if not line or _SKIP_RE.match(line):
        return None

    # Strip inline comments
    line = re.split(r"\s+#", line)[0].strip()
    line = re.split(r"\s+//", line)[0].strip()

    # ABP-style
    m = _ABP_BLOCK_RE.match(line)
    if m:
        domain = m.group(1).lower()
        if _is_valid_domain(domain):
            return Rule("DOMAIN-SUFFIX", domain)
        return None

    # QX leading-dot style
    m = _QX_DOT_RE.match(line)
    if m:
        domain = m.group(1).lower()
        if _is_valid_domain(domain):
            return Rule("DOMAIN-SUFFIX", domain)
        return None

    # Standard prefix,value[,policy]
    if "," in line:
        parts = line.split(",", 2)
        prefix = parts[0].strip().upper()
        value  = parts[1].strip().lower()

        canonical = _PREFIX_MAP.get(prefix)
        if canonical is None:
            return None   # unknown prefix

        if canonical in ("DOMAIN", "DOMAIN-SUFFIX"):
            # Strip trailing wildcard dot
            value = value.lstrip("*.")
            if not _is_valid_domain(value):
                return None
            if _is_ip(value):
                return None
            return Rule(canonical, value)

        if canonical == "DOMAIN-KEYWORD":
            return Rule(canonical, value)

        if canonical in ("IP-CIDR", "IP-CIDR6"):
            # Basic validation
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None
            return Rule(canonical, value)

    # Plain domain (no prefix, no comma)
    candidate = line.lower().lstrip("*.")
    if _is_valid_domain(candidate) and not _is_ip(candidate):
        return Rule("DOMAIN-SUFFIX", candidate)

    return None


# ──────────────────────────────────────────────
# Async fetching
# ──────────────────────────────────────────────
async def fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int = 30,
    retries: int = 3,
) -> str:
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                resp.raise_for_status()
                text = await resp.text(errors="replace")
                log.info("  ✓ %s  (%d bytes)", url.split("/")[-1], len(text))
                return text
        except Exception as exc:
            log.warning("  attempt %d/%d failed for %s: %s", attempt, retries, url, exc)
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)
    log.error("  ✗ giving up on %s", url)
    return ""


async def fetch_all(sources: list[dict]) -> list[tuple[str, str]]:
    """Returns list of (url, content)."""
    connector = aiohttp.TCPConnector(limit=10)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; rule-merger/1.0)"}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [fetch_url(session, s["url"]) for s in sources]
        results = await asyncio.gather(*tasks)
    return [(sources[i]["url"], results[i]) for i in range(len(sources))]


# ──────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────
def process(
    raw_pairs: list[tuple[str, str]],
) -> tuple[list[str], list[str], list[str], dict]:
    """
    Returns (domain_rules, keyword_rules, ip_rules, stats).
    domain_rules / keyword_rules / ip_rules are sorted lists of Loon-format strings.
    """
    trie = DomainTrie()
    keywords: set[str] = set()
    ip_rules: set[str] = set()

    stats = {
        "sources": len(raw_pairs),
        "raw_lines": 0,
        "parsed": 0,
        "domain_exact_inserted": 0,
        "domain_suffix_inserted": 0,
        "domain_redundant": 0,
        "keyword": 0,
        "ip": 0,
    }

    for url, content in raw_pairs:
        lines = content.splitlines()
        stats["raw_lines"] += len(lines)
        for raw in lines:
            rule = parse_line(raw)
            if rule is None:
                continue
            stats["parsed"] += 1

            if rule.kind == "DOMAIN-SUFFIX":
                ok = trie.insert_suffix(rule.value)
                if ok:
                    stats["domain_suffix_inserted"] += 1
                else:
                    stats["domain_redundant"] += 1

            elif rule.kind == "DOMAIN":
                ok = trie.insert_exact(rule.value)
                if ok:
                    stats["domain_exact_inserted"] += 1
                else:
                    stats["domain_redundant"] += 1

            elif rule.kind == "DOMAIN-KEYWORD":
                keywords.add(rule.value)
                stats["keyword"] += 1

            elif rule.kind in ("IP-CIDR", "IP-CIDR6"):
                ip_rules.add(f"{rule.kind},{rule.value},REJECT")
                stats["ip"] += 1

    # Emit domain rules from trie
    domain_out: list[str] = []
    for rtype, domain in trie.emit():
        domain_out.append(f"{rtype},{domain},REJECT")
    domain_out.sort()

    kw_out = sorted(f"DOMAIN-KEYWORD,{k},REJECT" for k in keywords)
    ip_out = sorted(ip_rules)

    stats["domain_output"] = len(domain_out)
    stats["keyword_output"] = len(kw_out)
    stats["ip_output"] = len(ip_out)
    stats["total_output"] = len(domain_out) + len(kw_out) + len(ip_out)

    return domain_out, kw_out, ip_out, stats


def write_output(
    path: Path,
    domain_rules: list[str],
    keyword_rules: list[str],
    ip_rules: list[str],
    sources: list[dict],
    stats: dict,
    elapsed: float,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header_lines = [
        "#!name=Merged Ad-Block Rules",
        "#!desc=Auto-generated by rule-merger. Do not edit manually.",
        f"# Updated : {now}",
        f"# Elapsed : {elapsed:.1f}s",
        f"# Sources : {stats['sources']}",
        f"# Raw lines parsed : {stats['raw_lines']:,}",
        f"# Rules parsed     : {stats['parsed']:,}",
        f"# Redundant dropped: {stats['domain_redundant']:,}",
        f"# Output rules     : {stats['total_output']:,}",
        f"#   DOMAIN/SUFFIX  : {stats['domain_output']:,}",
        f"#   DOMAIN-KEYWORD : {stats['keyword_output']:,}",
        f"#   IP-CIDR        : {stats['ip_output']:,}",
        "#",
        "# Source URLs:",
    ]
    for s in sources:
        header_lines.append(f"#   {s['url']}")
    header_lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(header_lines) + "\n")
        if domain_rules:
            f.write("\n# ── Domain / Domain-Suffix ──\n")
            f.write("\n".join(domain_rules) + "\n")
        if keyword_rules:
            f.write("\n# ── Domain-Keyword ──\n")
            f.write("\n".join(keyword_rules) + "\n")
        if ip_rules:
            f.write("\n# ── IP-CIDR ──\n")
            f.write("\n".join(ip_rules) + "\n")

    log.info("Output written: %s  (%d rules)", path, stats["total_output"])


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
def load_config(config_path: Path) -> dict:
    with config_path.open() as f:
        return yaml.safe_load(f)


async def main() -> None:
    repo_root   = Path(__file__).resolve().parents[1]
    config_path = repo_root / "scripts" / "config.yml"
    output_path = repo_root / "output" / "reject.list"

    cfg     = load_config(config_path)
    sources = cfg["sources"]

    log.info("Fetching %d source lists…", len(sources))
    t0 = time.monotonic()
    raw_pairs = await fetch_all(sources)

    log.info("Processing rules…")
    domain_rules, keyword_rules, ip_rules, stats = process(raw_pairs)
    elapsed = time.monotonic() - t0

    log.info(
        "Done in %.1fs — parsed %s rules, output %s (dropped %s redundant)",
        elapsed,
        f"{stats['parsed']:,}",
        f"{stats['total_output']:,}",
        f"{stats['domain_redundant']:,}",
    )

    write_output(output_path, domain_rules, keyword_rules, ip_rules, sources, stats, elapsed)


if __name__ == "__main__":
    asyncio.run(main())