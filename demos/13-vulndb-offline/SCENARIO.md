# Demo 13 — offline SBOM match against the bundled 262k-vuln DB

**Situation.** You are vetting a legacy appliance vendor on an **air-gapped**
review host with no internet. You still need to ground the SBOM in real
vulnerability data — so you use the database that ships inside vendorvet.

**Data.** `sbom.json` is a CycloneDX-lite component list for the appliance,
including a notoriously vulnerable Apache Struts 2 core
(home of CVE-2017-5638, the Equifax RCE) and an old Spring Beans.

**Command (no network, no cache):**

```bash
vendorvet vulndb match demos/13-vulndb-offline/sbom.json
```

**Expected verdict.** `CRITICAL` (exit `2`). The match resolves real records from
the bundled `cognis_vulndb.jsonl.gz`, led by:

```
[Maven] org.apache.struts:struts2-core@2.3.31  CVE-2017-5638  CVSS 10.0 (critical)
```

Every CVE shown is a real OSV/GHSA record committed in the repo — this command
makes **zero** network calls and needs **no** prior `feeds update`.

> Note: `vulndb match` reports all known vulns for a package (name-level match);
> use it for fast offline triage, then `feeds enrich` for live, version-precise
> OSV results plus the CISA-KEV actively-exploited flag.
