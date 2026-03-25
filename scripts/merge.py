#!/usr/bin/env python3
"""
Ad-block rule merger for Loon
- Fetches HTTP sources concurrently (aiohttp) or sequentially (urllib fallback)
- Reads local file sources (path:)
- Normalises Loon / Surge / QX / Shadowrocket / ABP / hosts formats → Loon
- Semantic dedup via reversed-label domain trie (DOMAIN-SUFFIX subsumes DOMAIN)
- Custom local deny list bypasses trie (always kept)
- Writes single output/reject.list
"""

import asyncio
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    import urllib.request

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent
SOURCES    = ROOT / "sources.yaml"
OUTPUT_DIR = ROOT / "output"
OUTPUT     = OUTPUT_DIR / "reject.list"

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("merger")

# ── constants ─────────────────────────────────────────────────────────────────
TIMEOUT = 30

# QX / Shadowrocket prefix → Loon prefix
_QX_MAP = {
    "HOST":          "DOMAIN",
    "HOST-SUFFIX":   "DOMAIN-SUFFIX",
    "HOST-KEYWORD":  "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
}

_VALID_PREFIXES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
    "USER-AGENT", "URL-REGEX", "PROCESS-NAME",
}

# Fast-path skip: blank / comment / section header / ABP exception / cosmetic
_SKIP_RE = re.compile(
    r"^\s*($|#|//|;|\[|!|@@|##|#\$|#@|^\|[^|])",
    re.IGNORECASE,
)

# Pre-compiled splitter for comma-or-space separated rules
_SPLIT_RE = re.compile(r"[,\s]+")

# Hosts file loopback prefixes to recognise
_HOSTS_PREFIX = ("0.0.0.0 ", "127.0.0.1 ", "::1 ", "fe80::1%lo0 ")

# Domains to ignore when parsing hosts files
_HOSTS_SKIP = frozenset({
    "localhost", "local", "broadcasthost", "0.0.0.0",
    "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
})


# ── normalisation ─────────────────────────────────────────────────────────────
def normalise_line(raw: str) -> str | None:
    """Return canonical Loon rule string, or None to discard."""
    line = raw.strip()

    if _SKIP_RE.match(line):
        return None

    # Strip inline comments
    line = re.split(r"\s+#|\s+//", line)[0].strip()
    if not line:
        return None

    # ── hosts format: "0.0.0.0 ads.example.com" ──────────────────────────────
    for pfx in _HOSTS_PREFIX:
        if line.startswith(pfx):
            parts = line.split()
            if len(parts) < 2:
                return None
            domain = parts[1].lower()
            if domain in _HOSTS_SKIP:
                return None
            return f"DOMAIN,{domain}"

    # ── ABP format: "||ads.example.com^" ─────────────────────────────────────
    if line.startswith("||"):
        inner = line[2:].split("$")[0].rstrip("^").lower()
        if "/" in inner or "*" in inner or not inner:
            return None
        inner = inner.split(":")[0]  # strip port
        return f"DOMAIN-SUFFIX,{inner}"

    # ── Loon / Surge / QX / Shadowrocket format ───────────────────────────────
    parts = _SPLIT_RE.split(line, maxsplit=2)
    if len(parts) < 2:
        return None

    prefix = parts[0].upper()
    value  = parts[1].strip().lower()
    prefix = _QX_MAP.get(prefix, prefix)

    if prefix not in _VALID_PREFIXES or not value:
        return None

# ── Loon / Surge / QX / Shadowrocket format ───────────────────────────────
    parts = _SPLIT_RE.split(line, maxsplit=2)
    if len(parts) < 2:
        return None

    prefix = parts[0].upper()
    value  = parts[1].strip().lower()
    prefix = _QX_MAP.get(prefix, prefix)

    if prefix not in _VALID_PREFIXES or not value:
        return None

    # ── 新增：wildcard domain fix ─────────────────────────────────────────────
    if prefix == "DOMAIN" and "*" in value:
        value = value.lstrip("*").lstrip(".")
        if not value:
            return None
        prefix = "DOMAIN-WILDCARD"
    # ─────────────────────────────────────────────────────────────────────────
    return f"{prefix},{value}"


# ── domain trie for semantic dedup ────────────────────────────────────────────
class DomainTrie:
    """
    Reversed-label trie.
      DOMAIN-SUFFIX,example.com  marks node; subsumes all subdomains & exact
      DOMAIN,ads.example.com     dropped if any ancestor is suffix-blocked
      All other rule types bypass the trie entirely
    """
    __slots__ = ("children", "suffix_blocked")

    def __init__(self):
        self.children: dict[str, "DomainTrie"] = {}
        self.suffix_blocked: bool = False

    @staticmethod
    def _labels(domain: str) -> list[str]:
        return domain.rstrip(".").split(".")[::-1]

    def try_insert(self, rule: str) -> bool:
        """Return True = keep, False = redundant."""
        prefix, _, value = rule.partition(",")

        if prefix not in ("DOMAIN", "DOMAIN-SUFFIX"):
            return True

        labels = self._labels(value)

        if prefix == "DOMAIN-SUFFIX":
            return self._insert_suffix(labels)
        else:
            return self._insert_exact(labels)

    def _insert_suffix(self, labels: list[str]) -> bool:
        node = self
        for label in labels:
            if node.suffix_blocked:
                return False
            node = node.children.setdefault(label, DomainTrie())
        if node.suffix_blocked:
            return False
        node.suffix_blocked = True
        node.children.clear()  # prune redundant subtree
        return True

    def _insert_exact(self, labels: list[str]) -> bool:
        node = self
        for label in labels:
            if node.suffix_blocked:
                return False
            if label not in node.children:
                return True    # path absent → not covered
            node = node.children[label]
        return True


# ── fetching ──────────────────────────────────────────────────────────────────
async def _fetch_http(session, name: str, url: str) -> tuple[str, list[str]]:
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)
        ) as r:
            r.raise_for_status()
            text  = await r.text(errors="replace")
            rules = [n for line in text.splitlines() if (n := normalise_line(line))]
            log.info("%-35s  fetched %7d rules", name, len(rules))
            return name, rules
    except Exception as exc:
        log.warning("%-35s  FAILED – %s", name, exc)
        return name, []


async def _fetch_local(name: str, rel_path: str) -> tuple[str, list[str]]:
    p = ROOT / rel_path
    if not p.exists():
        log.warning("%-35s  file not found: %s", name, p)
        return name, []
    text  = p.read_text(encoding="utf-8", errors="replace")
    rules = [n for line in text.splitlines() if (n := normalise_line(line))]
    log.info("%-35s  loaded  %7d rules", name, len(rules))
    return name, rules


async def fetch_all_async(sources: list[dict]) -> dict[str, list[str]]:
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for s in sources:
            if "url" in s:
                tasks.append(_fetch_http(session, s["name"], s["url"]))
            elif "path" in s:
                tasks.append(_fetch_local(s["name"], s["path"]))
        results = await asyncio.gather(*tasks)
    return dict(results)


def fetch_all_sync(sources: list[dict]) -> dict[str, list[str]]:
    """Fallback: sequential urllib, no aiohttp needed."""
    out = {}
    for s in sources:
        name = s["name"]
        if "path" in s:
            p = ROOT / s["path"]
            if not p.exists():
                log.warning("%-35s  file not found: %s", name, p)
                out[name] = []
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            out[name] = [n for line in text.splitlines() if (n := normalise_line(line))]
            log.info("%-35s  loaded  %7d rules", name, len(out[name]))
            continue
        try:
            req = urllib.request.Request(
                s["url"], headers={"User-Agent": "rule-merger/2.0"}
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            rules = [n for line in text.splitlines() if (n := normalise_line(line))]
            log.info("%-35s  fetched %7d rules", name, len(rules))
            out[name] = rules
        except Exception as exc:
            log.warning("%-35s  FAILED – %s", name, exc)
            out[name] = []
    return out


# ── merge ─────────────────────────────────────────────────────────────────────
def merge(results: dict[str, list[str]], custom_name: str | None) -> list[str]:
    """
    Pass 1 – all non-custom sources through DomainTrie semantic dedup
    Pass 2 – custom source appended directly, bypassing trie
    """
    trie       = DomainTrie()
    merged     = []
    total_in   = 0
    total_drop = 0

    custom_rules = results.pop(custom_name, []) if custom_name else []

    for rules in results.values():
        for rule in rules:
            total_in += 1
            if trie.try_insert(rule):
                merged.append(rule)
            else:
                total_drop += 1

    log.info(
        "Trie dedup: %d in → %d kept, %d redundant dropped",
        total_in, len(merged), total_drop,
    )

    if custom_rules:
        merged.extend(custom_rules)
        log.info("Custom rules appended: %d (bypass trie)", len(custom_rules))

    return merged


# ── output ────────────────────────────────────────────────────────────────────
def write_output(rules: list[str], sources: list[dict]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    source_lines = "\n".join(
        f"#   [{i+1:02d}] {s['name']}: {s.get('url', s.get('path', ''))}"
        for i, s in enumerate(sources)
    )

    header = (
        f"# {'='*60}\n"
        f"#  Ad-block reject rules – Loon format\n"
        f"#  Generated : {now}\n"
        f"#  Rules     : {len(rules):,}\n"
        f"#  Sources   :\n"
        f"{source_lines}\n"
        f"# {'='*60}\n\n"
    )

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
        f.write("\n")

    log.info("Written %d rules → %s", len(rules), OUTPUT)


# ── entrypoint ────────────────────────────────────────────────────────────────
def load_sources() -> tuple[list[dict], str | None]:
    with open(SOURCES, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    active      = [s for s in cfg["sources"] if s.get("enabled", True)]
    custom_name = next(
        (s["name"] for s in active if s.get("custom", False)), None
    )
    log.info(
        "Loaded %d active source(s)%s",
        len(active),
        f"  (custom: {custom_name})" if custom_name else "",
    )
    return active, custom_name


def main() -> None:
    sources, custom_name = load_sources()

    if HAS_AIOHTTP:
        results = asyncio.run(fetch_all_async(sources))
    else:
        log.warning("aiohttp not found – falling back to sequential urllib")
        results = fetch_all_sync(sources)

    failed = [n for n, r in results.items() if not r]
    if failed:
        log.warning("No rules returned from: %s", ", ".join(failed))

    merged = merge(results, custom_name)

    if not merged:
        log.error("Zero rules after merge – aborting to protect existing output")
        sys.exit(1)

    write_output(merged, sources)
    log.info("Done. Total unique rules: %d", len(merged))


if __name__ == "__main__":
    main()