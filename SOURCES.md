# Sources

## Vulnerability data feeds (consumed by `vendorvet feeds`)

Authoritative, keyless feeds wired into the SBOM enrichment layer. Fetched over
HTTPS, cached to disk, and re-served offline for edge / air-gap deployment.
Defensive / authorized-use intelligence only.

- **osv** — OSV.dev vulnerability query · `https://api.osv.dev/v1/query` ·
  package+version → known vulns across PyPI/npm/Maven/Go/crates.io/…
- **cisa-kev** — CISA Known Exploited Vulnerabilities catalog ·
  `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
  (JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) ·
  CVEs observed actively exploited in the wild.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Supply Chain
- **feed** · https://www.supplychaindive.com/feeds/news/
- **feed** · https://www.freightwaves.com/news/feed
- **live search** · `port congestion shipping delay 2026`
- **live search** · `tariff supply chain disruption`
- **live search** · `semiconductor export control`
- **api** · https://comtradeapi.un.org (UN Comtrade, free key)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

