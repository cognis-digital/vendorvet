// Rust port of the vendorvet questionnaire risk engine — zero deps, one binary.
//
// Mirrors `vendorvet questionnaire <file>`: same weighted control catalog, the
// same unanswered=half-penalty rule, the same data-classification multiplier and
// tier thresholds. JSON is parsed by a tiny built-in reader (no serde dep) so the
// crate builds offline with only the standard library.
//
//   cargo run -- questionnaire.json
//   cargo run -- questionnaire.json --format json
//
// Exit codes: 0 low/moderate, 2 high/critical, 1 usage/IO error.
use std::collections::BTreeMap;
use std::{env, fs, process};

// (key, label, weight, true_is_safe) — identical to core.py CONTROL_CATALOG.
const CATALOG: &[(&str, &str, f64, bool)] = &[
    ("soc2_type2", "SOC 2 Type II report on file", 10.0, true),
    ("iso27001", "ISO 27001 certified", 6.0, true),
    ("encryption_at_rest", "Data encrypted at rest", 9.0, true),
    ("encryption_in_transit", "Data encrypted in transit (TLS)", 9.0, true),
    ("mfa_enforced", "MFA enforced for all staff", 8.0, true),
    ("pentest_annual", "Independent pen test within 12 months", 7.0, true),
    ("incident_response_plan", "Documented incident response plan", 6.0, true),
    ("breach_notification_sla", "Contractual breach-notification SLA", 7.0, true),
    ("subprocessor_list", "Maintains public subprocessor list", 4.0, true),
    ("data_retention_policy", "Defined data retention/deletion policy", 5.0, true),
    ("vuln_mgmt_program", "Formal vulnerability management program", 6.0, true),
    ("employee_security_training", "Annual security awareness training", 4.0, true),
    ("shares_data_with_third_parties", "Shares customer data with 3rd parties", 8.0, false),
    ("prior_breach_24mo", "Disclosed breach in last 24 months", 9.0, false),
];

fn class_mult(c: &str) -> Option<f64> {
    match c {
        "public" => Some(0.6),
        "internal" => Some(0.85),
        "confidential" => Some(1.1),
        "restricted" => Some(1.35),
        _ => None,
    }
}

fn tier_for(score: f64) -> &'static str {
    if score >= 70.0 {
        "critical"
    } else if score >= 45.0 {
        "high"
    } else if score >= 20.0 {
        "moderate"
    } else {
        "low"
    }
}

fn round2(f: f64) -> f64 {
    (f * 100.0).round() / 100.0
}

// --- tiny JSON reader: enough for {"vendor":str,"data_classification":str,
//     "answers":{key:bool,...}}. Returns (vendor, class, answers map). ---
fn parse(src: &str) -> Result<(String, String, BTreeMap<String, bool>), String> {
    let mut vendor = String::from("unknown vendor");
    let mut class = String::from("internal");
    let mut answers: BTreeMap<String, bool> = BTreeMap::new();

    let top = extract_string_field(src, "vendor");
    if let Some(v) = top {
        vendor = v;
    }
    if let Some(c) = extract_string_field(src, "data_classification") {
        class = c;
    }
    // Find the "answers" object body.
    if let Some(idx) = src.find("\"answers\"") {
        let after = &src[idx..];
        if let Some(ob) = after.find('{') {
            let body = &after[ob + 1..];
            let mut depth = 1;
            let mut end = 0;
            for (i, ch) in body.char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            for pair in parse_bool_pairs(&body[..end]) {
                answers.insert(pair.0, pair.1);
            }
        }
    } else {
        return Err("questionnaire 'answers' must be an object".into());
    }
    Ok((vendor, class, answers))
}

fn extract_string_field(src: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let i = src.find(&needle)?;
    let rest = &src[i + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let val = &after[1..];
    let end = val.find('"')?;
    Some(val[..end].to_string())
}

fn parse_bool_pairs(body: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // read key
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            let key = body[start..j].to_string();
            // find colon then a true/false token
            let mut k = j + 1;
            while k < bytes.len() && bytes[k] != b':' {
                k += 1;
            }
            let after = body[k + 1..].trim_start();
            if after.starts_with("true") {
                out.push((key, true));
            } else if after.starts_with("false") {
                out.push((key, false));
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut format = "table".to_string();
    let mut rest: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--format" {
            if let Some(f) = it.next() {
                format = f.clone();
            }
        } else {
            rest.push(a.clone());
        }
    }
    if rest.len() < 2 || rest[0] != "questionnaire" {
        eprintln!("usage: vendorvet questionnaire <file> [--format json]");
        process::exit(1);
    }
    let src = match fs::read_to_string(&rest[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };
    let (vendor, class, answers) = match parse(&src) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };
    let mult = match class_mult(&class) {
        Some(m) => m,
        None => {
            eprintln!("error: data_classification must be public|internal|confidential|restricted");
            process::exit(1);
        }
    };

    let mut total_weight = 0.0;
    let mut penalty = 0.0;
    let mut answered = 0;
    for (key, _label, weight, true_is_safe) in CATALOG {
        total_weight += weight;
        match answers.get(*key) {
            Some(v) => {
                answered += 1;
                if *v != *true_is_safe {
                    penalty += weight;
                }
            }
            None => penalty += weight * 0.5,
        }
    }
    let raw = round2(100.0 * penalty / total_weight);
    let residual = round2((raw * mult).min(100.0));
    let tier = tier_for(residual);

    if format == "json" {
        println!("{{");
        println!("  \"vendor\": \"{}\",", vendor);
        println!("  \"data_classification\": \"{}\",", class);
        println!("  \"raw_score\": {},", raw);
        println!("  \"inherent_multiplier\": {},", mult);
        println!("  \"residual_score\": {},", residual);
        println!("  \"tier\": \"{}\",", tier);
        println!("  \"answered\": {},", answered);
        println!("  \"total_controls\": {}", CATALOG.len());
        println!("}}");
    } else {
        println!("Vendor:           {}", vendor);
        println!("Data class:       {} (x{})", class, mult);
        println!("Controls answered:{}/{}", answered, CATALOG.len());
        println!("Residual score:   {}/100", residual);
        println!("Risk tier:        {}", tier);
    }
    if tier == "high" || tier == "critical" {
        process::exit(2);
    }
}
