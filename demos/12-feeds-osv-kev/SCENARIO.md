# Demo 12 — live feed enrichment (OSV + CISA-KEV), runs offline

A vendor ships an SBOM. Instead of a hand-maintained advisory file, VENDORVET
resolves each component against **OSV.dev** for real, current advisories and then
flags any CVE that appears in the **CISA Known Exploited Vulnerabilities** catalog
(i.e. actively exploited in the wild). A KEV hit escalates the verdict to CRITICAL.

This demo runs fully **offline** from the committed fixture cache — no network.

```bash
# Point the feed cache at the committed fixtures (air-gap / CI mode):
export COGNIS_FEEDS_CACHE=tests/fixtures/feeds-cache

# Enrich the SBOM offline:
vendorvet feeds enrich demos/12-feeds-osv-kev/sbom.json --offline
# -> log4j-core 2.14.1  CVE-2021-44228  CVSS 10.0  [!! CISA-KEV: ACTIVELY EXPLOITED]
#    Verdict: CRITICAL
```

Components:
- `log4j-core 2.14.1` -> CVE-2021-44228 (Log4Shell) — in CISA-KEV -> CRITICAL.
- `django 3.0` -> several OSV advisories (CVE-2020-9402 SQLi, CVE-2020-13596 XSS),
  none KEV-listed -> contributes to CVSS but not the exploited flag.
- `requests 2.31.0` -> clean (no OSV vulns).

## Online / refresh

```bash
vendorvet feeds update osv cisa-kev      # fetch + cache the live feeds
vendorvet feeds enrich demos/12-feeds-osv-kev/sbom.json   # uses live cache
```

## Air-gap transfer

On a connected host, build a snapshot and carry it to the enclave:

```bash
python -m vendorvet.datafeeds snapshot-export feeds.tar.gz
# (sneakernet feeds.tar.gz across the air gap)
python -m vendorvet.datafeeds snapshot-import feeds.tar.gz
vendorvet feeds enrich sbom.json --offline
```
