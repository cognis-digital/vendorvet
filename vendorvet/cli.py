"""Command-line interface for VENDORVET.

Subcommands
-----------
  questionnaire  Score a vendor security questionnaire JSON.
  sbom           Cross-reference an SBOM against an advisory feed.
  assess         Combined verdict from questionnaire + optional SBOM.

Global flags: --version, --format {table,json}
Exit codes: 0 ok (low/moderate), 2 high/critical risk, 1 usage/IO error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    RiskTier,
    assess_questionnaire,
    assess_vendor,
    crossref_sbom,
    load_json_file,
    to_dict,
)

_HIGH_RISK = {RiskTier.HIGH.value, RiskTier.CRITICAL.value}


def _emit(data: Any, fmt: str, table_lines: List[str]) -> None:
    if fmt == "json":
        print(json.dumps(to_dict(data), indent=2, sort_keys=True))
    else:
        print("\n".join(table_lines))


def _q_table(r) -> List[str]:
    lines = [
        f"Vendor:           {r.vendor}",
        f"Data class:       {r.data_classification} (x{r.inherent_multiplier})",
        f"Controls answered:{r.answered}/{r.total_controls}",
        f"Residual score:   {r.residual_score}/100",
        f"Risk tier:        {r.tier.value.upper()}",
    ]
    if r.gaps:
        lines.append("Gaps:")
        lines.extend(f"  - {g}" for g in r.gaps)
    return lines


def _s_table(r) -> List[str]:
    lines = [
        f"Components scanned: {r.components_scanned}",
        f"Vulnerable:         {len(r.vulnerable)}",
        f"Max CVSS:           {r.max_cvss} ({r.severity})",
    ]
    for c in r.vulnerable:
        lines.append(f"  ! {c.name}@{c.version}  {c.cve}  CVSS {c.cvss} ({c.severity})")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME, description="SMB third-party risk vetting."
    )
    p.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    p.add_argument("--format", choices=["table", "json"], default="table")
    sub = p.add_subparsers(dest="command")

    pq = sub.add_parser("questionnaire", help="Score a questionnaire JSON file.")
    pq.add_argument("file")

    ps = sub.add_parser("sbom", help="Cross-reference SBOM vs advisories.")
    ps.add_argument("sbom_file")
    ps.add_argument("advisories_file")

    pa = sub.add_parser("assess", help="Combined questionnaire + SBOM verdict.")
    pa.add_argument("questionnaire_file")
    pa.add_argument("--sbom")
    pa.add_argument("--advisories")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "questionnaire":
            r = assess_questionnaire(load_json_file(args.file))
            _emit(r, args.format, _q_table(r))
            return 2 if r.tier.value in _HIGH_RISK else 0

        if args.command == "sbom":
            r = crossref_sbom(
                load_json_file(args.sbom_file),
                load_json_file(args.advisories_file),
            )
            _emit(r, args.format, _s_table(r))
            return 2 if r.severity in ("high", "critical") else 0

        if args.command == "assess":
            q = load_json_file(args.questionnaire_file)
            sbom = load_json_file(args.sbom) if args.sbom else None
            adv = load_json_file(args.advisories) if args.advisories else None
            r = assess_vendor(q, sbom, adv)
            table = [
                f"Vendor:        {r.vendor}",
                f"Overall score: {r.overall_score}/100",
                f"Overall tier:  {r.overall_tier.value.upper()}",
                f"Recommend:     {r.recommendation}",
            ]
            if r.questionnaire:
                table.append("-- questionnaire --")
                table.extend(_q_table(r.questionnaire))
            if r.sbom:
                table.append("-- sbom --")
                table.extend(_s_table(r.sbom))
            _emit(r, args.format, table)
            return 2 if r.overall_tier.value in _HIGH_RISK else 0

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
