"""Core risk engine for VENDORVET.

No third-party dependencies. All scoring is deterministic and explainable.

Questionnaire model
-------------------
A questionnaire is a JSON object::

    {
      "vendor": "Acme SaaS",
      "data_classification": "confidential",  # public|internal|confidential|restricted
      "answers": {
        "soc2_type2": true,
        "encryption_at_rest": true,
        "mfa_enforced": false,
        ...
      }
    }

Each control carries a weight and a polarity (whether "true" is good).
The inherent risk of the data classification scales the residual score.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskTier(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# control_key -> (human label, weight, must_be_true_to_be_safe)
CONTROL_CATALOG: Dict[str, tuple] = {
    "soc2_type2": ("SOC 2 Type II report on file", 10, True),
    "iso27001": ("ISO 27001 certified", 6, True),
    "encryption_at_rest": ("Data encrypted at rest", 9, True),
    "encryption_in_transit": ("Data encrypted in transit (TLS)", 9, True),
    "mfa_enforced": ("MFA enforced for all staff", 8, True),
    "pentest_annual": ("Independent pen test within 12 months", 7, True),
    "incident_response_plan": ("Documented incident response plan", 6, True),
    "breach_notification_sla": ("Contractual breach-notification SLA", 7, True),
    "subprocessor_list": ("Maintains public subprocessor list", 4, True),
    "data_retention_policy": ("Defined data retention/deletion policy", 5, True),
    "vuln_mgmt_program": ("Formal vulnerability management program", 6, True),
    "employee_security_training": ("Annual security awareness training", 4, True),
    "shares_data_with_third_parties": (
        "Shares customer data with 3rd parties", 8, False
    ),
    "prior_breach_24mo": ("Disclosed breach in last 24 months", 9, False),
}

# Inherent-risk multiplier by classification of data the vendor touches.
DATA_CLASS_MULTIPLIER: Dict[str, float] = {
    "public": 0.6,
    "internal": 0.85,
    "confidential": 1.1,
    "restricted": 1.35,
}

CVSS_TIER = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


@dataclass
class ControlFinding:
    key: str
    label: str
    weight: int
    answered: bool
    satisfied: bool
    penalty: float


@dataclass
class QuestionnaireResult:
    vendor: str
    data_classification: str
    raw_score: float            # 0..100, higher = more residual risk
    inherent_multiplier: float
    residual_score: float       # 0..100 after inherent scaling
    tier: RiskTier
    answered: int
    total_controls: int
    findings: List[ControlFinding] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)


@dataclass
class SbomComponent:
    name: str
    version: str
    cve: str
    cvss: float
    severity: str


@dataclass
class SbomResult:
    components_scanned: int
    vulnerable: List[SbomComponent] = field(default_factory=list)
    max_cvss: float = 0.0
    severity: str = "none"


@dataclass
class VendorAssessment:
    vendor: str
    overall_tier: RiskTier
    overall_score: float
    questionnaire: Optional[QuestionnaireResult]
    sbom: Optional[SbomResult]
    recommendation: str


def _severity_for(cvss: float) -> str:
    for threshold, name in CVSS_TIER:
        if cvss >= threshold:
            return name
    return "none"


def _tier_for_score(score: float) -> RiskTier:
    if score >= 70:
        return RiskTier.CRITICAL
    if score >= 45:
        return RiskTier.HIGH
    if score >= 20:
        return RiskTier.MODERATE
    return RiskTier.LOW


def assess_questionnaire(doc: Dict[str, Any]) -> QuestionnaireResult:
    """Score a vendor security questionnaire.

    Residual risk = (sum of penalties for failed/unanswered controls
    normalized to 0..100) * inherent multiplier, clamped to 100.
    """
    if not isinstance(doc, dict):
        raise ValueError("questionnaire must be a JSON object")
    vendor = str(doc.get("vendor") or "unknown vendor")
    classification = str(doc.get("data_classification") or "internal").lower()
    if classification not in DATA_CLASS_MULTIPLIER:
        raise ValueError(
            "data_classification must be one of "
            + ", ".join(sorted(DATA_CLASS_MULTIPLIER))
        )
    answers = doc.get("answers")
    if not isinstance(answers, dict):
        raise ValueError("questionnaire 'answers' must be an object")

    total_weight = sum(w for _, w, _ in CONTROL_CATALOG.values())
    penalty_sum = 0.0
    answered = 0
    findings: List[ControlFinding] = []
    gaps: List[str] = []

    for key, (label, weight, true_is_safe) in CONTROL_CATALOG.items():
        if key in answers:
            answered += 1
            val = bool(answers[key])
            satisfied = (val == true_is_safe)
            penalty = 0.0 if satisfied else float(weight)
        else:
            # Unanswered controls are treated as half-penalty (unknown == risk).
            satisfied = False
            penalty = weight * 0.5
            gaps.append(label + " (unanswered)")
        if not satisfied and penalty > 0 and key in answers:
            gaps.append(label)
        penalty_sum += penalty
        findings.append(
            ControlFinding(
                key=key, label=label, weight=weight,
                answered=(key in answers), satisfied=satisfied,
                penalty=round(penalty, 2),
            )
        )

    raw_score = round(100.0 * penalty_sum / total_weight, 2)
    mult = DATA_CLASS_MULTIPLIER[classification]
    residual = round(min(100.0, raw_score * mult), 2)

    return QuestionnaireResult(
        vendor=vendor,
        data_classification=classification,
        raw_score=raw_score,
        inherent_multiplier=mult,
        residual_score=residual,
        tier=_tier_for_score(residual),
        answered=answered,
        total_controls=len(CONTROL_CATALOG),
        findings=findings,
        gaps=gaps,
    )


def crossref_sbom(sbom: Dict[str, Any], advisories: Dict[str, Any]) -> SbomResult:
    """Cross-reference SBOM components against a known-vuln advisory feed.

    SBOM (CycloneDX-lite)::
        {"components": [{"name": "log4j-core", "version": "2.14.1"}, ...]}

    Advisories::
        {"log4j-core": [{"affected": ["2.0".."2.14.1"], "cve": "CVE-2021-44228",
                          "cvss": 10.0, "versions": ["2.14.1"]}], ...}

    A component matches if its exact version appears in an advisory's
    "versions" list for that package name.
    """
    if not isinstance(sbom, dict):
        raise ValueError("SBOM must be a JSON object")
    if not isinstance(advisories, dict):
        raise ValueError("advisories must be a JSON object")
    comps = sbom.get("components")
    if not isinstance(comps, list):
        raise ValueError("SBOM must contain a 'components' array")

    vulnerable: List[SbomComponent] = []
    max_cvss = 0.0
    for c in comps:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "").strip()
        version = str(c.get("version") or "").strip()
        if not name:
            continue
        adv_list = advisories.get(name, [])
        if not isinstance(adv_list, list):
            continue
        for adv in adv_list:
            if not isinstance(adv, dict):
                continue
            affected_versions = {str(v) for v in adv.get("versions", [])}
            if version in affected_versions:
                try:
                    cvss = float(adv.get("cvss", 0.0))
                except (TypeError, ValueError):
                    cvss = 0.0
                cvss = max(0.0, min(10.0, cvss))
                max_cvss = max(max_cvss, cvss)
                vulnerable.append(
                    SbomComponent(
                        name=name, version=version,
                        cve=str(adv.get("cve") or "UNKNOWN"),
                        cvss=cvss, severity=_severity_for(cvss),
                    )
                )

    vulnerable.sort(key=lambda x: x.cvss, reverse=True)
    scanned = sum(
        1 for c in comps if isinstance(c, dict) and c.get("name")
    )
    return SbomResult(
        components_scanned=scanned,
        vulnerable=vulnerable,
        max_cvss=round(max_cvss, 1),
        severity=_severity_for(max_cvss),
    )


def _recommend(tier: RiskTier) -> str:
    return {
        RiskTier.LOW: "Approve. Standard annual re-review.",
        RiskTier.MODERATE: "Approve with conditions. Track remediation of gaps.",
        RiskTier.HIGH: "Do not approve until material gaps are remediated.",
        RiskTier.CRITICAL: "Reject / escalate. Critical exposure or active vuln.",
    }[tier]


def assess_vendor(
    questionnaire: Optional[Dict[str, Any]] = None,
    sbom: Optional[Dict[str, Any]] = None,
    advisories: Optional[Dict[str, Any]] = None,
) -> VendorAssessment:
    """Combine questionnaire residual risk and SBOM exposure into one verdict.

    SBOM contributes a score boost based on the worst CVSS found
    (cvss 10 -> +100 contribution). Overall = max(questionnaire, sbom-derived).

    At least one of questionnaire or sbom must be provided.
    """
    if questionnaire is None and sbom is None:
        raise ValueError("at least one of questionnaire or sbom must be provided")
    q_result = (
        assess_questionnaire(questionnaire) if questionnaire is not None else None
    )
    s_result = None
    if sbom is not None:
        s_result = crossref_sbom(sbom, advisories or {})

    q_score = q_result.residual_score if q_result else 0.0
    s_score = (s_result.max_cvss / 10.0 * 100.0) if s_result else 0.0
    overall = round(max(q_score, s_score), 2)
    tier = _tier_for_score(overall)

    vendor = "unknown vendor"
    if q_result:
        vendor = q_result.vendor
    elif sbom is not None:
        vendor = str(sbom.get("vendor") or vendor)

    return VendorAssessment(
        vendor=vendor,
        overall_tier=tier,
        overall_score=overall,
        questionnaire=q_result,
        sbom=s_result,
        recommendation=_recommend(tier),
    )


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses/enums to plain JSON-able structures."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


def load_json_file(path: str) -> Dict[str, Any]:
    """Load and parse a JSON file; raise clear errors on failure."""
    if not path:
        raise ValueError("file path must not be empty")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise OSError(f"file not found: {path}")
    except PermissionError:
        raise OSError(f"permission denied reading: {path}")
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"invalid JSON in {path!r}: {exc.msg}", exc.doc, exc.pos
        )
    if not isinstance(data, dict):
        raise ValueError(
            f"{path!r} must contain a JSON object (got {type(data).__name__})"
        )
    return data
