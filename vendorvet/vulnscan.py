"""Offline SBOM enrichment against the BUNDLED 262k-record vuln DB.

Where :mod:`vendorvet.feeds` enriches an SBOM by querying *live* OSV + CISA-KEV
(cache-backed, but ultimately network sourced), this module resolves the same
SBOM components against the **bundled** ``cognis_vulndb.jsonl.gz`` — ~262k real
OSV/GHSA records that ship inside the wheel.

That makes a grounded verdict available the moment the repo is cloned, with
**zero network and no cache priming** — the true air-gap / clean-room path. It is
purely a lookup over committed data: passive, offline, no scanning.

    from vendorvet.vulnscan import match_sbom, lookup_cve
    lookup_cve("CVE-2021-44228")                # -> records from the bundle
    match_sbom({"components": [{"name": "log4j-core", ...}]})

Defensive / authorized-use intelligence only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .vulndb_local import VulnDB
from . import feeds as _feeds  # reuse CVSS-vector scoring + ecosystem aliases

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# A single module-level DB so the (indexed) load is paid once per process.
_DB: Optional[VulnDB] = None


def db() -> VulnDB:
    global _DB
    if _DB is None:
        _DB = VulnDB()
    return _DB


def _best_cvss(record: Dict[str, Any]) -> float:
    """Compute a CVSS base score from a bundled record's severity vector."""
    sev = record.get("severity")
    if not sev:
        return 0.0
    if isinstance(sev, (int, float)):
        return round(float(sev), 1)
    # Bundle stores a CVSS *vector* string (possibly with a trailing /E:.. etc).
    return _feeds._score_from_vector(str(sev))


def _cve_for(record: Dict[str, Any]) -> str:
    for alias in record.get("aliases", []) or []:
        if _CVE_RE.fullmatch(str(alias)):
            return str(alias)
    rid = str(record.get("id", ""))
    return rid or "UNKNOWN"


# --------------------------------------------------------------------------- #
# direct lookups over the bundle
# --------------------------------------------------------------------------- #
def lookup_cve(cve: str) -> List[Dict[str, Any]]:
    """Return all bundled records whose id/alias matches ``cve`` (or a GHSA id)."""
    return db().by_cve(cve)


def lookup_package(name: str, ecosystem: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return bundled records affecting ``name`` (optionally in one ecosystem)."""
    eco = _feeds._normalize_ecosystem(ecosystem) if ecosystem else None
    return db().by_package(name, ecosystem=eco)


def stats() -> Dict[str, Any]:
    """Aggregate counts over the bundle: total, ecosystems, with-CVE, scored."""
    total = 0
    ecosystems: Dict[str, int] = {}
    with_cve = 0
    scored = 0
    for r in db():
        total += 1
        eco = r.get("ecosystem") or "unknown"
        ecosystems[eco] = ecosystems.get(eco, 0) + 1
        if any(_CVE_RE.fullmatch(str(a)) for a in (r.get("aliases") or [])):
            with_cve += 1
        if r.get("severity"):
            scored += 1
    return {
        "records": total,
        "ecosystems": dict(sorted(ecosystems.items(), key=lambda kv: -kv[1])),
        "with_cve_alias": with_cve,
        "with_severity": scored,
    }


# --------------------------------------------------------------------------- #
# SBOM matching
# --------------------------------------------------------------------------- #
@dataclass
class BundleFinding:
    component: str
    version: str
    ecosystem: Optional[str]
    cve: str
    osv_id: str
    summary: str
    cvss: float
    severity: str


@dataclass
class BundleScan:
    components_scanned: int
    findings: List[BundleFinding] = field(default_factory=list)
    max_cvss: float = 0.0
    severity: str = "none"
    verdict: str = "low"


_CVSS_TIER = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def _severity_for(cvss: float) -> str:
    for threshold, name in _CVSS_TIER:
        if cvss >= threshold:
            return name
    return "none"


def match_sbom(sbom: Dict[str, Any]) -> BundleScan:
    """Match every SBOM component against the bundled DB by package name.

    Fully offline: only the committed ``cognis_vulndb.jsonl.gz`` is consulted.
    A component matches when its package name appears in a bundled record's
    affected-packages list for the same (normalized) ecosystem when one is given.
    Returns the worst-CVSS-first finding list and an overall verdict tier.
    """
    comps = sbom.get("components")
    if not isinstance(comps, list):
        raise ValueError("SBOM must contain a 'components' array")

    findings: List[BundleFinding] = []
    max_cvss = 0.0
    scanned = 0
    seen: set[tuple] = set()

    for c in comps:
        name = str(c.get("name", "")).strip()
        if not name:
            continue
        scanned += 1
        version = str(c.get("version", "")).strip()
        ecosystem = c.get("ecosystem") or c.get("type") or c.get("purl_type")
        # A purl-ish name "org.apache.logging.log4j:log4j-core" or bare name.
        candidates = {name}
        if ":" in name:
            candidates.add(name.rsplit(":", 1)[-1])
        records: List[Dict[str, Any]] = []
        for cand in candidates:
            records.extend(lookup_package(cand, ecosystem))
        for r in records:
            cve = _cve_for(r)
            osv_id = str(r.get("id", ""))
            key = (name, version, cve or osv_id)
            if key in seen:
                continue
            seen.add(key)
            cvss = _best_cvss(r)
            max_cvss = max(max_cvss, cvss)
            findings.append(
                BundleFinding(
                    component=name,
                    version=version,
                    ecosystem=_feeds._normalize_ecosystem(ecosystem) if ecosystem else None,
                    cve=cve,
                    osv_id=osv_id,
                    summary=(r.get("summary") or "")[:160],
                    cvss=cvss,
                    severity=_severity_for(cvss),
                )
            )

    findings.sort(key=lambda f: f.cvss, reverse=True)
    sev = _severity_for(max_cvss)
    verdict = sev
    if verdict == "medium":
        verdict = "moderate"
    elif verdict == "none":
        verdict = "low"

    return BundleScan(
        components_scanned=scanned,
        findings=findings,
        max_cvss=round(max_cvss, 1),
        severity=sev,
        verdict=verdict,
    )
