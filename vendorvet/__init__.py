"""VENDORVET - Third-party / vendor risk management for SMBs.

Scores vendor security questionnaires, cross-references SBOM components
against a known-vulnerability feed, and emits an overall risk verdict.
"""
from .core import (
    assess_questionnaire,
    crossref_sbom,
    assess_vendor,
    RiskTier,
    QuestionnaireResult,
    SbomResult,
    VendorAssessment,
)

TOOL_NAME = "vendorvet"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "assess_questionnaire",
    "crossref_sbom",
    "assess_vendor",
    "RiskTier",
    "QuestionnaireResult",
    "SbomResult",
    "VendorAssessment",
]
