"""Real data-feed enrichment for VENDORVET (edge / air-gap deployable).

VENDORVET vets third-party software supply chains. This module wires two
authoritative, keyless vulnerability feeds from the bundled Cognis catalog
into the SBOM workflow so a verdict is grounded in *real, current* exposure
instead of a hand-maintained advisory file:

  * ``osv``      — OSV.dev (https://osv.dev) package+version -> known vulns
                   across PyPI / npm / Maven / Go / crates.io / ... ecosystems.
  * ``cisa-kev`` — CISA Known Exploited Vulnerabilities catalog
                   (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
                   the authoritative list of CVEs observed exploited in the wild.

REAL enrichment (``enrich_sbom``): every SBOM component is queried against OSV
for live advisories; each returned CVE is then cross-checked against CISA-KEV to
raise a ``known_exploited`` flag — the single most important escalation signal in
third-party risk. KEV hits are escalated to CRITICAL regardless of CVSS.

Edge / air-gap design (inherited from the bundled ``datafeeds`` module):
  * stdlib only (urllib) — drops into any environment, no pip deps.
  * disk cache (``COGNIS_FEEDS_CACHE``); ``offline=True`` serves cache only and
    never touches the network.
  * ``datafeeds.snapshot_export`` / ``snapshot_import`` move the cache across an
    air gap by sneakernet.

Only the two feed ids this tool consumes are exposed; all endpoints come from the
bundled catalog (``data_feeds_2026.json``) — none are invented here.

Defensive / authorized-use intelligence only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import datafeeds

# Feed ids this repo is wired to consume (must exist in the bundled catalog).
RELEVANT_FEEDS: tuple[str, ...] = ("osv", "cisa-kev")

# Map an SBOM component "ecosystem" / "purl"-ish hint to an OSV ecosystem.
_ECOSYSTEM_ALIASES: Dict[str, str] = {
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "npm": "npm", "node": "npm",
    "maven": "Maven", "java": "Maven",
    "go": "Go", "golang": "Go",
    "cargo": "crates.io", "crates": "crates.io", "rust": "crates.io",
    "nuget": "NuGet", "rubygems": "RubyGems", "gem": "RubyGems",
    "packagist": "Packagist", "composer": "Packagist",
    "hex": "Hex", "pub": "Pub",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def relevant_catalog() -> List[Dict[str, Any]]:
    """The bundled catalog entries this tool is allowed to use."""
    feeds = {f["id"]: f for f in datafeeds.load_catalog().get("feeds", [])}
    out = []
    for fid in RELEVANT_FEEDS:
        if fid in feeds:
            out.append(feeds[fid])
    return out


def _normalize_ecosystem(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return _ECOSYSTEM_ALIASES.get(str(value).strip().lower())


# --------------------------------------------------------------------------- #
# CISA-KEV
# --------------------------------------------------------------------------- #
def kev_index(*, offline: bool = False) -> Dict[str, Dict[str, Any]]:
    """Return {CVE-id: kev-record} from the CISA KEV catalog."""
    doc = datafeeds.get("cisa-kev", offline=offline)
    out: Dict[str, Dict[str, Any]] = {}
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            out[cve] = v
    return out


# --------------------------------------------------------------------------- #
# OSV
# --------------------------------------------------------------------------- #
def _cvss_score(severity: List[Dict[str, Any]]) -> float:
    """Best-effort numeric CVSS base score from an OSV severity[] vector list.

    OSV gives CVSS *vectors* (e.g. ``CVSS:3.1/AV:N/...``), not base scores, so we
    compute the base score from the vector. Returns 0.0 when none parseable.
    """
    best = 0.0
    for s in severity or []:
        score = _score_from_vector(str(s.get("score", "")))
        if score > best:
            best = score
    return round(best, 1)


# Minimal CVSS v3.x base-score calculator (stdlib only, no deps).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _score_from_vector(vector: str) -> float:
    if not vector.startswith("CVSS:3"):
        return 0.0
    parts = dict(
        p.split(":", 1) for p in vector.split("/")[1:] if ":" in p
    )
    try:
        scope_changed = parts.get("S") == "C"
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        ui = _UI[parts["UI"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return 0.0
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    # round up to one decimal (CVSS spec)
    import math
    return math.ceil(base * 10) / 10.0


def _cve_for(vuln: Dict[str, Any]) -> str:
    """Prefer a CVE alias; fall back to the OSV id."""
    for alias in vuln.get("aliases", []):
        if _CVE_RE.fullmatch(str(alias)):
            return str(alias)
    osv_id = str(vuln.get("id", ""))
    if _CVE_RE.fullmatch(osv_id):
        return osv_id
    return osv_id or "UNKNOWN"


def osv_query(name: str, version: str, ecosystem: Optional[str],
              *, offline: bool = False) -> List[Dict[str, Any]]:
    """Query OSV for one package@version. Returns the raw ``vulns`` list.

    Online: POSTs to OSV and caches the response keyed by package coordinates.
    Offline: serves the cached response for these exact coordinates only.
    """
    eco = _normalize_ecosystem(ecosystem)
    pkg: Dict[str, Any] = {"name": name}
    if eco:
        pkg["ecosystem"] = eco
    query = {"package": pkg, "version": version}

    # Per-coordinate cache id so each component can be re-served offline.
    # Strip dots too: datafeeds._paths uses Path.with_suffix, which would
    # otherwise treat a dotted version (e.g. "2.14.1") as a file suffix.
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", f"{eco or 'any'}-{name}-{version}")
    cache_id = f"osv-q-{safe}"

    data_path, meta_path = datafeeds._paths(cache_id)  # noqa: SLF001
    if offline:
        if not data_path.exists():
            raise FileNotFoundError(
                f"osv: no cached result for {name}@{version} ({eco or 'any'}) "
                "and offline=True"
            )
        raw = data_path.read_bytes()
    else:
        if data_path.exists():
            raw = data_path.read_bytes()
        else:
            raw = datafeeds.fetch(
                "https://api.osv.dev/v1/query",
                method="POST",
                data=json.dumps(query).encode(),
            )
            data_path.write_bytes(raw)
            meta_path.write_text(
                json.dumps({"feed": "osv", "query": query}), encoding="utf-8"
            )
    doc = json.loads(raw.decode("utf-8", "replace"))
    return doc.get("vulns", []) or []


# --------------------------------------------------------------------------- #
# enrichment data model
# --------------------------------------------------------------------------- #
@dataclass
class FeedFinding:
    component: str
    version: str
    ecosystem: Optional[str]
    cve: str
    osv_id: str
    summary: str
    cvss: float
    severity: str
    known_exploited: bool          # listed in CISA KEV
    kev_ransomware: Optional[str]  # KEV "knownRansomwareCampaignUse"
    kev_due_date: Optional[str]


@dataclass
class FeedScan:
    components_scanned: int
    findings: List[FeedFinding] = field(default_factory=list)
    max_cvss: float = 0.0
    severity: str = "none"
    known_exploited_count: int = 0
    verdict: str = "low"


_CVSS_TIER = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def _severity_for(cvss: float) -> str:
    for threshold, name in _CVSS_TIER:
        if cvss >= threshold:
            return name
    return "none"


def enrich_sbom(sbom: Dict[str, Any], *, offline: bool = False) -> FeedScan:
    """REAL enrichment: resolve each SBOM component against OSV, flag CISA-KEV.

    SBOM (CycloneDX-lite)::
        {"components": [
            {"name": "django", "version": "3.0", "ecosystem": "PyPI"}, ...]}

    For each component we pull live OSV advisories, compute a CVSS base score
    from the OSV severity vector, and set ``known_exploited`` when the CVE is in
    the CISA KEV catalog. A KEV hit escalates the verdict to CRITICAL because the
    vulnerability is being actively exploited.
    """
    comps = sbom.get("components")
    if not isinstance(comps, list):
        raise ValueError("SBOM must contain a 'components' array")

    kev = kev_index(offline=offline)
    findings: List[FeedFinding] = []
    max_cvss = 0.0
    scanned = 0

    for c in comps:
        name = str(c.get("name", "")).strip()
        if not name:
            continue
        version = str(c.get("version", "")).strip()
        ecosystem = c.get("ecosystem") or c.get("type") or c.get("purl_type")
        scanned += 1
        for v in osv_query(name, version, ecosystem, offline=offline):
            cve = _cve_for(v)
            cvss = _cvss_score(v.get("severity", []))
            max_cvss = max(max_cvss, cvss)
            kev_rec = kev.get(cve)
            findings.append(
                FeedFinding(
                    component=name,
                    version=version,
                    ecosystem=_normalize_ecosystem(ecosystem),
                    cve=cve,
                    osv_id=str(v.get("id", "")),
                    summary=(v.get("summary") or v.get("details") or "")[:160],
                    cvss=cvss,
                    severity=_severity_for(cvss),
                    known_exploited=kev_rec is not None,
                    kev_ransomware=(kev_rec or {}).get("knownRansomwareCampaignUse"),
                    kev_due_date=(kev_rec or {}).get("dueDate"),
                )
            )

    kev_count = sum(1 for f in findings if f.known_exploited)
    # KEV-listed = actively exploited -> always CRITICAL.
    if kev_count:
        verdict = "critical"
    else:
        verdict = _severity_for(max_cvss)
        if verdict == "medium":
            verdict = "moderate"
        elif verdict == "none":
            verdict = "low"

    # Sort: KEV first, then by CVSS desc.
    findings.sort(key=lambda f: (f.known_exploited, f.cvss), reverse=True)

    return FeedScan(
        components_scanned=scanned,
        findings=findings,
        max_cvss=round(max_cvss, 1),
        severity=_severity_for(max_cvss),
        known_exploited_count=kev_count,
        verdict=verdict,
    )
