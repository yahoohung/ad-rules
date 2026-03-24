# Merged Ad Rules

Auto-generated daily from multiple upstream lists, deduplicated via a **domain suffix trie** — not just string comparison.

## Output

|File                |Format|Description                         |
|--------------------|------|------------------------------------|
|`output/reject.list`|Loon  |Merged, trie-compressed reject rules|

Raw URL for Loon / Surge / Shadowrocket:

```
https://raw.githubusercontent.com/yahoohung/ad-rules/refs/heads/main/output/reject.list
```

## How it works

```
Fetch 7 upstream lists (async, parallel)
         ↓
Normalise all formats → Loon DOMAIN / DOMAIN-SUFFIX / IP-CIDR
         ↓
DOMAIN / DOMAIN-SUFFIX rules → Reversed-label Trie
  • insert DOMAIN-SUFFIX,example.com
      → mark ["com","example"] as suffix node
  • insert DOMAIN,ads.example.com
      → ancestor ["com","example"] is suffix node → REDUNDANT, discard
  • insert DOMAIN-SUFFIX,ads.example.com
      → same → REDUNDANT, discard
         ↓
IP-CIDR / IP-CIDR6 → plain set dedup
DOMAIN-KEYWORD     → plain set dedup
         ↓
Emit surviving rules → sorted → output/reject.list
```

This eliminates not just duplicate strings but **logically subsumed rules**,
producing a smaller and faster rule set for the proxy engine.

## Adding / removing sources

Edit **`scripts/config.yml`** — no Python changes needed:

```yaml
sources:
  - url: https://example.com/new-list.list
    note: New list description

  # Temporarily disable without deleting:
  # - url: https://old-list.com/rules.list
  #   enabled: false
```

## Supported input formats

|Format      |Example                           |
|------------|----------------------------------|
|Loon / Surge|`DOMAIN-SUFFIX,example.com,REJECT`|
|Shadowrocket|`HOST-SUFFIX,example.com,REJECT`  |
|Quantumult X|`.example.com`                    |
|AdBlock Plus|`||example.com^`                  |
|Plain domain|`example.com`                     |

## Schedule

Runs daily at **03:00 UTC** (11:00 HKT) via GitHub Actions.
Manual trigger available in the Actions tab.