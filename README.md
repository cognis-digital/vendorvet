<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=VENDORVET&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="VENDORVET"/>

# VENDORVET

### Third-party / vendor risk questionnaires with SBOM cross-ref

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Thirdparty++vendor+risk+questionnaires+with+SBOM+crossref;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-vendorvet.svg?color=6b46c1)](https://pypi.org/project/cognis-vendorvet/) [![CI](https://github.com/cognis-digital/vendorvet/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/vendorvet/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Compliance & GRC — get audit-ready and stay there, self-hosted.*

</div>

```bash
pip install cognis-vendorvet
vendorvet scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** (Python 3.9+):

   ```bash
   pip install vendorvet
   ```

2. **Score a security questionnaire.** Point `vendorvet questionnaire` at a vendor questionnaire JSON to get a residual risk score and tier:

   ```bash
   vendorvet questionnaire vendor_questionnaire.json
   ```

3. **Cross-reference an SBOM** against an advisory feed to find vulnerable components:

   ```bash
   vendorvet sbom vendor_sbom.json advisories.json
   ```

4. **Get a combined verdict** and read the output as JSON for tooling. `assess` merges the questionnaire with an optional SBOM:

   ```bash
   vendorvet --format json assess vendor_questionnaire.json --sbom vendor_sbom.json --advisories advisories.json | jq .tier
   ```

5. **Gate in CI.** The exit code is `0` for low/moderate risk, `2` for high/critical, and `1` on usage/IO errors — so a step fails the build when a vendor is high-risk:

   ```bash
   vendorvet assess vendor_questionnaire.json --sbom vendor_sbom.json --advisories advisories.json || echo "Vendor flagged high/critical risk"
   ```

6. **Export SARIF 2.1.0** for GitHub code scanning / any SARIF viewer. Add `--format sarif` to any subcommand:

   ```bash
   vendorvet --format sarif assess vendor_questionnaire.json \
       --sbom vendor_sbom.json --advisories advisories.json > vendorvet.sarif
   ```

   Each questionnaire gap and vulnerable component becomes a SARIF result; CVEs carry a `security-severity` property so GitHub renders the right badge. See [`demos/09-ci-gate-sarif`](demos/09-ci-gate-sarif) for a full Actions workflow.

## Worked examples (demos)

Every folder under [`demos/`](demos) is a runnable, real-use-case scenario
with a `SCENARIO.md` (where the data came from, the exact command, and the
expected verdict). They all use real, documented CVEs.

| Demo | Situation | Verdict |
|---|---|---|
| [`01-basic`](demos/01-basic) | SaaS with Log4Shell in its SBOM | CRITICAL (exit 2) |
| [`02-clean`](demos/02-clean) | Fully-attested vendor, zero gaps | LOW (exit 0) |
| [`03-mixed`](demos/03-mixed) | Mid-tier vendor, MFA/pentest gaps | MODERATE (exit 0) |
| [`04-payroll-saas`](demos/04-payroll-saas) | Strong payroll vendor, restricted PII, missing breach SLA | MODERATE (exit 0) |
| [`05-clean-vendor`](demos/05-clean-vendor) | Public-data vendor, patched SBOM | LOW (exit 0) |
| [`06-supply-chain-struts`](demos/06-supply-chain-struts) | SBOM-only: Apache Struts RCE (CVE-2017-5638) | CRITICAL (exit 2) |
| [`07-startup-unanswered`](demos/07-startup-unanswered) | Early-stage vendor leaves controls blank | HIGH (exit 2) |
| [`08-spring4shell`](demos/08-spring4shell) | Clean questionnaire, Spring4Shell in code | CRITICAL (exit 2) |
| [`09-ci-gate-sarif`](demos/09-ci-gate-sarif) | CI gate + SARIF upload (CVE-2021-45046) | CRITICAL (exit 2) |
| [`10-data-broker-restricted`](demos/10-data-broker-restricted) | Data broker, prior breach, shares data | HIGH (exit 2) |
| [`11-heartbleed-legacy`](demos/11-heartbleed-legacy) | Legacy appliance with Heartbleed OpenSSL | HIGH (exit 2) |
| [`12-feeds-osv-kev`](demos/12-feeds-osv-kev) | SBOM enriched from **live OSV + CISA-KEV** (runs offline) | CRITICAL (exit 2) |

```bash
# run any demo straight from a clone
python -m vendorvet assess demos/08-spring4shell/questionnaire.json \
    --sbom demos/08-spring4shell/sbom.json \
    --advisories demos/08-spring4shell/advisories.json
```


## Live feed enrichment (OSV + CISA-KEV) — edge / air-gap ready

The `sbom`/`assess` subcommands above cross-reference an SBOM against a
*hand-supplied* advisory file. The `feeds` subcommand instead grounds the verdict
in **real, current** vulnerability intelligence pulled from two authoritative,
keyless sources, then re-serves them **offline** so the tool keeps working on
disconnected / edge / air-gapped gear.

| Feed id | Source | URL |
|---|---|---|
| `osv` | OSV.dev — package+version → known vulns across PyPI/npm/Maven/Go/crates.io/… | `https://api.osv.dev/v1/query` |
| `cisa-kev` | CISA Known Exploited Vulnerabilities catalog (actively exploited in the wild) | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` |

**Real enrichment:** every SBOM component is resolved against OSV for live
advisories; each CVE is then checked against CISA-KEV. A KEV hit raises a
`known_exploited` flag and escalates the verdict to **CRITICAL** regardless of
CVSS — a vulnerability under active exploitation is the single strongest
third-party-risk escalation signal.

```bash
vendorvet feeds list                       # the two feeds this tool consumes
vendorvet feeds update osv cisa-kev        # fetch + cache (online)
vendorvet feeds enrich vendor_sbom.json    # live OSV + KEV enrichment
```

```text
$ vendorvet feeds enrich demos/12-feeds-osv-kev/sbom.json --offline
Components scanned:    3
Max CVSS:              10.0 (critical)
Known-exploited (KEV): 2
Verdict:               CRITICAL
  org.apache.logging.log4j:log4j-core@2.14.1  CVE-2021-44228  CVSS 10.0 (critical)  [!! CISA-KEV: ACTIVELY EXPLOITED]
      remediate by 2021-12-24; ransomware: Known
  django@3.0  CVE-2020-9402  CVSS 7.5 (high)
```

Exit code is `2` when the verdict is high/critical (CI-gate friendly).

### Offline / air-gap workflow

`datafeeds` (bundled, stdlib-only) caches every fetch to disk and can re-serve it
with **zero network**:

```bash
export COGNIS_FEEDS_CACHE=/secure/feeds-cache     # where the cache lives
vendorvet feeds update osv cisa-kev               # on a connected host
vendorvet feeds enrich sbom.json --offline        # serve from cache only
```

To move intelligence into a disconnected enclave, snapshot the cache and carry it
across the air gap by sneakernet:

```bash
# connected host
python -m vendorvet.datafeeds snapshot-export feeds.tar.gz
# air-gapped host
export COGNIS_FEEDS_CACHE=/secure/feeds-cache
python -m vendorvet.datafeeds snapshot-import feeds.tar.gz
vendorvet feeds enrich sbom.json --offline
```

The committed test suite runs **fully offline** against trimmed fixtures under
[`tests/fixtures/feeds-cache/`](tests/fixtures/feeds-cache) — no test touches the
network. *Defensive / authorized-use intelligence only.*


## Contents

- [Why vendorvet?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why vendorvet?

TPRM for SMBs

`vendorvet` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Score security questionnaires (weighted controls, inherent-risk multiplier)
- ✅ Cross-reference SBOMs against an advisory feed (exact-version matching)
- ✅ Combined vendor verdict (questionnaire + SBOM) with recommendation
- ✅ Output as **table · JSON · SARIF 2.1.0** (`--format`)
- ✅ CI-friendly exit codes (0 / 2 / 1) for procurement gates
- ✅ 11 runnable real-use-case demos in [`demos/`](demos)
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-vendorvet
vendorvet --version
vendorvet scan .                       # scan current project
vendorvet scan . --format json         # machine-readable
vendorvet scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ vendorvet scan .
  [HIGH    ] VEN-001  example finding             (./src/app.py)
  [MEDIUM  ] VEN-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[vendorvet<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`vendorvet` is interoperable with every popular way of using AI:

- **MCP server** — `vendorvet mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `vendorvet scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis vendorvet** | OneTrust TPRM |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **OneTrust TPRM**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`vendorvet mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/vendorvet.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/vendorvet.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/vendorvet.git" # uv
pip install cognis-vendorvet                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/vendorvet:latest --help        # Docker
brew install cognis-digital/tap/vendorvet                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/vendorvet/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/vendorvet` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`soc2box`](https://github.com/cognis-digital/soc2box) — SOC 2 evidence collector and control tracker, self-hosted
- [`gdprkit`](https://github.com/cognis-digital/gdprkit) — GDPR/CCPA DSAR, RoPA, and cookie-consent toolkit
- [`policyforge`](https://github.com/cognis-digital/policyforge) — Auto-generate security policies from a short questionnaire
- [`auditrail`](https://github.com/cognis-digital/auditrail) — Tamper-evident audit-log aggregator with hash-chained attestation
- [`frameworkmap`](https://github.com/cognis-digital/frameworkmap) — Crosswalk controls across NIST, ISO 27001, SOC 2, CMMC, PCI
- [`dpiaforge`](https://github.com/cognis-digital/dpiaforge) — DPIA and EU AI Act impact-assessment generator

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `vendorvet` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
