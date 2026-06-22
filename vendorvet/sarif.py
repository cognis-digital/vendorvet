"""SARIF 2.1.0 export for VENDORVET.

Turns a vendorvet assessment (questionnaire gaps + SBOM vulnerable
components) into a SARIF 2.1.0 log so the results can be uploaded to
GitHub code scanning, Azure DevOps, or any SARIF-aware viewer.

SARIF spec: OASIS "Static Analysis Results Interchange Format (SARIF)
Version 2.1.0". Only the subset needed for findings is emitted; the
document validates against the published 2.1.0 schema.

No third-party dependencies; standard library only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    QuestionnaireResult,
    SbomResult,
    VendorAssessment,
    assess_questionnaire,
    assess_vendor,
    crossref_sbom,
)

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/cognis-digital/vendorvet"

# vendorvet tier -> SARIF result level + numeric security-severity (0..10).
_LEVEL = {
    "low": ("note", "2.0"),
    "moderate": ("warning", "5.0"),
    "high": ("error", "8.0"),
    "critical": ("error", "9.5"),
}
# CVSS severity bucket -> SARIF level.
_CVSS_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "none": "note",
}


def _result(rule_id: str, level: str, message: str,
            uri: str, security_severity: Optional[str] = None,
            properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri}
            }
        }],
    }
    props: Dict[str, Any] = dict(properties or {})
    if security_severity is not None:
        props["security-severity"] = security_severity
    if props:
        res["properties"] = props
    return res


def _rules_for(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for r in results:
        rid = r["ruleId"]
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": rid.replace("-", "").replace("_", ""),
                "shortDescription": {"text": rid},
                "defaultConfiguration": {"level": r.get("level", "warning")},
            }
    return list(seen.values())


def _questionnaire_results(q: QuestionnaireResult, uri: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # one summary result for the residual risk tier
    level, sev = _LEVEL.get(q.tier.value, ("warning", "5.0"))
    out.append(_result(
        "VEN-Q-RESIDUAL", level,
        f"{q.vendor}: residual risk {q.residual_score}/100 "
        f"(tier {q.tier.value}, data class {q.data_classification})",
        uri, security_severity=sev,
        properties={"vendor": q.vendor, "tier": q.tier.value,
                    "residual_score": q.residual_score},
    ))
    # one result per failed/unanswered control
    for f in q.findings:
        if f.satisfied or f.penalty <= 0:
            continue
        unanswered = not f.answered
        rid = "VEN-Q-UNANSWERED" if unanswered else "VEN-Q-GAP"
        lvl = "note" if unanswered else "warning"
        suffix = " (unanswered)" if unanswered else ""
        out.append(_result(
            rid, lvl, f"{f.label}{suffix} [{f.key}]", uri,
            properties={"control": f.key, "weight": f.weight,
                        "penalty": f.penalty},
        ))
    return out


def _sbom_results(s: SbomResult, uri: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in s.vulnerable:
        out.append(_result(
            c.cve, _CVSS_LEVEL.get(c.severity, "warning"),
            f"{c.name}@{c.version} affected by {c.cve} "
            f"(CVSS {c.cvss}, {c.severity})",
            uri, security_severity=str(c.cvss),
            properties={"component": c.name, "version": c.version,
                        "cve": c.cve, "cvss": c.cvss, "severity": c.severity},
        ))
    return out


def to_sarif(assessment: VendorAssessment,
             questionnaire_uri: str = "questionnaire.json",
             sbom_uri: str = "sbom.json") -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from a VendorAssessment."""
    results: List[Dict[str, Any]] = []
    if assessment.questionnaire is not None:
        results.extend(_questionnaire_results(assessment.questionnaire, questionnaire_uri))
    if assessment.sbom is not None:
        results.extend(_sbom_results(assessment.sbom, sbom_uri))

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": INFORMATION_URI,
                    "rules": _rules_for(results),
                }
            },
            "results": results,
            "properties": {
                "vendor": assessment.vendor,
                "overall_tier": assessment.overall_tier.value,
                "overall_score": assessment.overall_score,
                "recommendation": assessment.recommendation,
            },
        }],
    }


def questionnaire_to_sarif(doc: Dict[str, Any],
                           uri: str = "questionnaire.json") -> Dict[str, Any]:
    """SARIF for a standalone questionnaire (no SBOM)."""
    q = assess_questionnaire(doc)
    assessment = assess_vendor(questionnaire=doc)
    return to_sarif(assessment, questionnaire_uri=uri)


def sbom_to_sarif(sbom: Dict[str, Any], advisories: Dict[str, Any],
                  uri: str = "sbom.json") -> Dict[str, Any]:
    """SARIF for a standalone SBOM cross-reference (no questionnaire)."""
    crossref_sbom(sbom, advisories)  # validates shape, raises on bad input
    assessment = assess_vendor(sbom=sbom, advisories=advisories)
    return to_sarif(assessment, sbom_uri=uri)
