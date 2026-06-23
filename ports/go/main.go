// Go port of the vendorvet questionnaire risk engine — single binary, zero deps.
//
// Mirrors the reference Python `vendorvet questionnaire <file>` command:
// scores a vendor security-questionnaire JSON into a residual risk score
// (0..100) and tier, using the same weighted control catalog, the same
// unanswered=half-penalty rule, and the same data-classification multiplier.
//
//	go run . questionnaire.json
//	go run . questionnaire.json --format json
//
// Exit codes: 0 low/moderate, 2 high/critical, 1 usage/IO error.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type control struct {
	label      string
	weight     float64
	trueIsSafe bool
}

// control_key -> (label, weight, must_be_true_to_be_safe) — identical to core.py.
var catalog = map[string]control{
	"soc2_type2":                    {"SOC 2 Type II report on file", 10, true},
	"iso27001":                      {"ISO 27001 certified", 6, true},
	"encryption_at_rest":            {"Data encrypted at rest", 9, true},
	"encryption_in_transit":         {"Data encrypted in transit (TLS)", 9, true},
	"mfa_enforced":                  {"MFA enforced for all staff", 8, true},
	"pentest_annual":                {"Independent pen test within 12 months", 7, true},
	"incident_response_plan":        {"Documented incident response plan", 6, true},
	"breach_notification_sla":       {"Contractual breach-notification SLA", 7, true},
	"subprocessor_list":             {"Maintains public subprocessor list", 4, true},
	"data_retention_policy":         {"Defined data retention/deletion policy", 5, true},
	"vuln_mgmt_program":             {"Formal vulnerability management program", 6, true},
	"employee_security_training":    {"Annual security awareness training", 4, true},
	"shares_data_with_third_parties": {"Shares customer data with 3rd parties", 8, false},
	"prior_breach_24mo":             {"Disclosed breach in last 24 months", 9, false},
}

var classMult = map[string]float64{
	"public": 0.6, "internal": 0.85, "confidential": 1.1, "restricted": 1.35,
}

func tierFor(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 45:
		return "high"
	case score >= 20:
		return "moderate"
	default:
		return "low"
	}
}

type result struct {
	Vendor             string   `json:"vendor"`
	DataClassification string   `json:"data_classification"`
	RawScore           float64  `json:"raw_score"`
	InherentMultiplier float64  `json:"inherent_multiplier"`
	ResidualScore      float64  `json:"residual_score"`
	Tier               string   `json:"tier"`
	Answered           int      `json:"answered"`
	TotalControls      int      `json:"total_controls"`
	Gaps               []string `json:"gaps"`
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func assess(doc map[string]any) (result, error) {
	vendor, _ := doc["vendor"].(string)
	if vendor == "" {
		vendor = "unknown vendor"
	}
	class, _ := doc["data_classification"].(string)
	if class == "" {
		class = "internal"
	}
	mult, ok := classMult[class]
	if !ok {
		return result{}, fmt.Errorf("data_classification must be public|internal|confidential|restricted")
	}
	answers, ok := doc["answers"].(map[string]any)
	if !ok {
		return result{}, fmt.Errorf("questionnaire 'answers' must be an object")
	}

	var totalWeight, penaltySum float64
	for _, c := range catalog {
		totalWeight += c.weight
	}
	answered := 0
	gaps := []string{}
	keys := make([]string, 0, len(catalog))
	for k := range catalog {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := catalog[k]
		raw, present := answers[k]
		if present {
			answered++
			val, _ := raw.(bool)
			satisfied := val == c.trueIsSafe
			if !satisfied {
				penaltySum += c.weight
				gaps = append(gaps, c.label)
			}
		} else {
			penaltySum += c.weight * 0.5
			gaps = append(gaps, c.label+" (unanswered)")
		}
	}
	rawScore := round2(100.0 * penaltySum / totalWeight)
	residual := round2(rawScore * mult)
	if residual > 100 {
		residual = 100
	}
	return result{
		Vendor: vendor, DataClassification: class, RawScore: rawScore,
		InherentMultiplier: mult, ResidualScore: residual, Tier: tierFor(residual),
		Answered: answered, TotalControls: len(catalog), Gaps: gaps,
	}, nil
}

func main() {
	args := os.Args[1:]
	format := "table"
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		} else {
			rest = append(rest, args[i])
		}
	}
	if len(rest) < 2 || rest[0] != "questionnaire" {
		fmt.Fprintln(os.Stderr, "usage: vendorvet questionnaire <file> [--format json]")
		os.Exit(1)
	}
	b, err := os.ReadFile(rest[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	r, err := assess(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if format == "json" {
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Vendor:           %s\n", r.Vendor)
		fmt.Printf("Data class:       %s (x%g)\n", r.DataClassification, r.InherentMultiplier)
		fmt.Printf("Controls answered:%d/%d\n", r.Answered, r.TotalControls)
		fmt.Printf("Residual score:   %g/100\n", r.ResidualScore)
		fmt.Printf("Risk tier:        %s\n", r.Tier)
	}
	if r.Tier == "high" || r.Tier == "critical" {
		os.Exit(2)
	}
}
