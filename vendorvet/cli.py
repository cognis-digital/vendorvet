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
from .sarif import to_sarif
from . import datafeeds, feeds as feedmod, vulnscan

_HIGH_RISK = {RiskTier.HIGH.value, RiskTier.CRITICAL.value}
_FEED_HIGH = {"high", "critical"}


def _emit(data: Any, fmt: str, table_lines: List[str],
          sarif: Optional[Any] = None) -> None:
    if fmt == "json":
        print(json.dumps(to_dict(data), indent=2, sort_keys=True))
    elif fmt == "sarif":
        print(json.dumps(sarif if sarif is not None else {}, indent=2, sort_keys=True))
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
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="SMB third-party risk vetting.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json", "sarif"], default="table")
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

    pf = sub.add_parser(
        "feeds",
        help="Real vuln feeds (OSV + CISA-KEV) for SBOM enrichment.",
    )
    fsub = pf.add_subparsers(dest="feeds_command")
    fsub.add_parser("list", help="List the feeds this tool consumes.")
    fu = fsub.add_parser("update", help="Fetch + cache the consumed feeds.")
    fu.add_argument("ids", nargs="*", help="feed id(s); default: all consumed")
    fg = fsub.add_parser("get", help="Print a cached/fetched feed.")
    fg.add_argument("id")
    fg.add_argument("--offline", action="store_true")
    fe = fsub.add_parser(
        "enrich",
        help="Enrich an SBOM with live OSV vulns + CISA-KEV exploited flag.",
    )
    fe.add_argument("sbom_file")
    fe.add_argument("--offline", action="store_true")

    # vulndb: 100% offline lookups against the bundled 262k-record OSV corpus.
    pv = sub.add_parser(
        "vulndb",
        help="Bundled 262k-vuln DB lookups (fully offline, no network/cache).",
    )
    vsub = pv.add_subparsers(dest="vulndb_command")
    vsub.add_parser("stats", help="Summarize the bundled vuln database.")
    vc = vsub.add_parser("cve", help="Look up a CVE/GHSA id in the bundle.")
    vc.add_argument("id")
    vp = vsub.add_parser("package", help="List bundled vulns affecting a package.")
    vp.add_argument("name")
    vp.add_argument("--ecosystem")
    vm = vsub.add_parser(
        "match", help="Match an SBOM against the bundled DB (offline)."
    )
    vm.add_argument("sbom_file")
    return p


def _fs_table(r) -> List[str]:
    lines = [
        f"Components scanned:    {r.components_scanned}",
        f"Max CVSS:              {r.max_cvss} ({r.severity})",
        f"Known-exploited (KEV): {r.known_exploited_count}",
        f"Verdict:               {r.verdict.upper()}",
    ]
    for f in r.findings:
        kev = "  [!! CISA-KEV: ACTIVELY EXPLOITED]" if f.known_exploited else ""
        lines.append(
            f"  {f.component}@{f.version}  {f.cve}  CVSS {f.cvss} ({f.severity}){kev}"
        )
        if f.known_exploited and f.kev_due_date:
            ransom = (f.kev_ransomware or "Unknown")
            lines.append(f"      remediate by {f.kev_due_date}; ransomware: {ransom}")
    return lines


def _feeds_command(args, fmt: str) -> int:
    """Handle the `feeds` subcommand restricted to OSV + CISA-KEV."""
    sub = getattr(args, "feeds_command", None)
    if sub == "list":
        cat = feedmod.relevant_catalog()
        if fmt == "json":
            print(json.dumps(cat, indent=2, sort_keys=True))
        else:
            print("Feeds consumed by vendorvet (defensive / authorized-use):")
            for f in cat:
                age = datafeeds.cached_age_hours(f["id"])
                fresh = "uncached" if age is None else f"{age:.1f}h old"
                print(f"  {f['id']:10} [{fresh:9}] {f['name']}")
                print(f"             {f['url']}")
        return 0

    if sub == "update":
        ids = args.ids or list(feedmod.RELEVANT_FEEDS)
        rc = 0
        for fid in ids:
            if fid not in feedmod.RELEVANT_FEEDS:
                print(f"error: {fid!r} is not a feed vendorvet consumes "
                      f"({', '.join(feedmod.RELEVANT_FEEDS)})", file=sys.stderr)
                rc = 1
                continue
            try:
                pth = datafeeds.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr)
                rc = 1
        return rc

    if sub == "get":
        if args.id not in feedmod.RELEVANT_FEEDS:
            print(f"error: {args.id!r} is not a feed vendorvet consumes "
                  f"({', '.join(feedmod.RELEVANT_FEEDS)})", file=sys.stderr)
            return 1
        try:
            data = datafeeds.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(data, indent=2)[:4000] if isinstance(data, (dict, list))
              else str(data)[:4000])
        return 0

    if sub == "enrich":
        sbom = load_json_file(args.sbom_file)
        try:
            r = feedmod.enrich_sbom(sbom, offline=args.offline)
        except (FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _emit(r, fmt, _fs_table(r))
        return 2 if r.verdict in _FEED_HIGH else 0

    print("error: feeds subcommand required (list|update|get|enrich)",
          file=sys.stderr)
    return 1


def _vm_table(r) -> List[str]:
    lines = [
        f"Components scanned: {r.components_scanned}",
        f"Matched vulns:      {len(r.findings)}",
        f"Max CVSS:           {r.max_cvss} ({r.severity})",
        f"Verdict:            {r.verdict.upper()}",
        "(source: bundled cognis_vulndb.jsonl.gz - fully offline)",
    ]
    for f in r.findings[:50]:
        eco = f"[{f.ecosystem}] " if f.ecosystem else ""
        lines.append(
            f"  {eco}{f.component}@{f.version or '*'}  {f.cve}  "
            f"CVSS {f.cvss} ({f.severity})"
        )
    return lines


def _vulndb_command(args, fmt: str) -> int:
    """Handle the offline `vulndb` subcommand over the bundled corpus."""
    sub = getattr(args, "vulndb_command", None)
    if sub == "stats":
        s = vulnscan.stats()
        if fmt == "json":
            print(json.dumps(s, indent=2, sort_keys=True))
        else:
            print(f"Bundled vulnerability database (offline):")
            print(f"  records:          {s['records']}")
            print(f"  with CVE alias:   {s['with_cve_alias']}")
            print(f"  with severity:    {s['with_severity']}")
            print(f"  ecosystems:")
            for eco, n in s["ecosystems"].items():
                print(f"    {eco:14} {n}")
        return 0

    if sub == "cve":
        recs = vulnscan.lookup_cve(args.id)
        if fmt == "json":
            print(json.dumps(recs, indent=2, sort_keys=True))
        else:
            if not recs:
                print(f"no bundled record for {args.id}")
            for r in recs:
                aliases = ", ".join(r.get("aliases", []))
                print(f"  {r.get('id')}  [{r.get('ecosystem')}]  ({aliases})")
                print(f"    {(r.get('summary') or '')[:200]}")
                pkgs = ", ".join((r.get('packages') or [])[:6])
                print(f"    packages: {pkgs}")
        return 0 if recs else 1

    if sub == "package":
        recs = vulnscan.lookup_package(args.name, args.ecosystem)
        if fmt == "json":
            print(json.dumps(recs, indent=2, sort_keys=True))
        else:
            print(f"{len(recs)} bundled vuln(s) affecting {args.name}"
                  + (f" ({args.ecosystem})" if args.ecosystem else ""))
            for r in recs[:50]:
                aliases = ", ".join(r.get("aliases", []))
                print(f"  {r.get('id')}  [{r.get('ecosystem')}]  {aliases}")
        return 0

    if sub == "match":
        sbom = load_json_file(args.sbom_file)
        r = vulnscan.match_sbom(sbom)
        _emit(r, fmt, _vm_table(r))
        return 2 if r.verdict in _FEED_HIGH else 0

    print("error: vulndb subcommand required (stats|cve|package|match)",
          file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "questionnaire":
            doc = load_json_file(args.file)
            r = assess_questionnaire(doc)
            sarif = to_sarif(assess_vendor(questionnaire=doc),
                             questionnaire_uri=args.file) if args.format == "sarif" else None
            _emit(r, args.format, _q_table(r), sarif=sarif)
            return 2 if r.tier.value in _HIGH_RISK else 0

        if args.command == "sbom":
            sbom_doc = load_json_file(args.sbom_file)
            adv_doc = load_json_file(args.advisories_file)
            r = crossref_sbom(sbom_doc, adv_doc)
            sarif = to_sarif(assess_vendor(sbom=sbom_doc, advisories=adv_doc),
                             sbom_uri=args.sbom_file) if args.format == "sarif" else None
            _emit(r, args.format, _s_table(r), sarif=sarif)
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
            sarif = to_sarif(
                r,
                questionnaire_uri=args.questionnaire_file,
                sbom_uri=(args.sbom or "sbom.json"),
            ) if args.format == "sarif" else None
            _emit(r, args.format, table, sarif=sarif)
            return 2 if r.overall_tier.value in _HIGH_RISK else 0

        if args.command == "feeds":
            return _feeds_command(args, args.format)

        if args.command == "vulndb":
            return _vulndb_command(args, args.format)

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
