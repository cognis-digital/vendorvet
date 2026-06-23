#!/usr/bin/env node
// JavaScript / Node port of the vendorvet questionnaire risk engine.
// Mirrors `vendorvet questionnaire <file>`: same control catalog, same
// unanswered=half-penalty rule, same data-classification multiplier, same tiers.
//
//   node index.js questionnaire.json
//   node index.js questionnaire.json --format json
//
// Exit codes: 0 low/moderate, 2 high/critical, 1 usage/IO error.
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

// key -> [label, weight, trueIsSafe] — identical to core.py CONTROL_CATALOG.
export const CATALOG = {
  soc2_type2: ["SOC 2 Type II report on file", 10, true],
  iso27001: ["ISO 27001 certified", 6, true],
  encryption_at_rest: ["Data encrypted at rest", 9, true],
  encryption_in_transit: ["Data encrypted in transit (TLS)", 9, true],
  mfa_enforced: ["MFA enforced for all staff", 8, true],
  pentest_annual: ["Independent pen test within 12 months", 7, true],
  incident_response_plan: ["Documented incident response plan", 6, true],
  breach_notification_sla: ["Contractual breach-notification SLA", 7, true],
  subprocessor_list: ["Maintains public subprocessor list", 4, true],
  data_retention_policy: ["Defined data retention/deletion policy", 5, true],
  vuln_mgmt_program: ["Formal vulnerability management program", 6, true],
  employee_security_training: ["Annual security awareness training", 4, true],
  shares_data_with_third_parties: ["Shares customer data with 3rd parties", 8, false],
  prior_breach_24mo: ["Disclosed breach in last 24 months", 9, false],
};

export const CLASS_MULT = { public: 0.6, internal: 0.85, confidential: 1.1, restricted: 1.35 };

export function tierFor(score) {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "moderate";
  return "low";
}

const round2 = (f) => Math.round(f * 100) / 100;

export function assess(doc) {
  const vendor = doc.vendor || "unknown vendor";
  const cls = (doc.data_classification || "internal").toLowerCase();
  const mult = CLASS_MULT[cls];
  if (mult === undefined)
    throw new Error("data_classification must be public|internal|confidential|restricted");
  const answers = doc.answers;
  if (typeof answers !== "object" || answers === null || Array.isArray(answers))
    throw new Error("questionnaire 'answers' must be an object");

  let totalWeight = 0, penalty = 0, answered = 0;
  const gaps = [];
  for (const [key, [label, weight, trueIsSafe]] of Object.entries(CATALOG)) {
    totalWeight += weight;
    if (key in answers) {
      answered++;
      const satisfied = Boolean(answers[key]) === trueIsSafe;
      if (!satisfied) { penalty += weight; gaps.push(label); }
    } else {
      penalty += weight * 0.5;
      gaps.push(label + " (unanswered)");
    }
  }
  const raw_score = round2((100 * penalty) / totalWeight);
  const residual_score = Math.min(100, round2(raw_score * mult));
  return {
    vendor, data_classification: cls, raw_score, inherent_multiplier: mult,
    residual_score, tier: tierFor(residual_score),
    answered, total_controls: Object.keys(CATALOG).length, gaps,
  };
}

const _invoked = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (_invoked) {
  const args = process.argv.slice(2);
  let format = "table";
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--format") { format = args[++i]; } else rest.push(args[i]);
  }
  if (rest.length < 2 || rest[0] !== "questionnaire") {
    console.error("usage: vendorvet questionnaire <file> [--format json]");
    process.exit(1);
  }
  let r;
  try {
    r = assess(JSON.parse(readFileSync(rest[1], "utf8")));
  } catch (e) {
    console.error("error: " + e.message);
    process.exit(1);
  }
  if (format === "json") {
    console.log(JSON.stringify(r, null, 2));
  } else {
    console.log(`Vendor:           ${r.vendor}`);
    console.log(`Data class:       ${r.data_classification} (x${r.inherent_multiplier})`);
    console.log(`Controls answered:${r.answered}/${r.total_controls}`);
    console.log(`Residual score:   ${r.residual_score}/100`);
    console.log(`Risk tier:        ${r.tier}`);
  }
  if (r.tier === "high" || r.tier === "critical") process.exit(2);
}
