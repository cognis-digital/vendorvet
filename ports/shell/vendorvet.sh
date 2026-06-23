#!/usr/bin/env sh
# POSIX shell port of the vendorvet questionnaire risk engine (requires `jq`).
#
# Mirrors `vendorvet questionnaire <file>`: same weighted control catalog, the
# same unanswered=half-penalty rule, the same data-classification multiplier and
# tier thresholds. All arithmetic is done in jq.
#
#   ./vendorvet.sh questionnaire questionnaire.json
#   ./vendorvet.sh questionnaire questionnaire.json --format json
#
# Exit codes: 0 low/moderate, 2 high/critical, 1 usage/IO error.
set -eu

FORMAT="table"
CMD=""
FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    *) if [ -z "$CMD" ]; then CMD="$1"; elif [ -z "$FILE" ]; then FILE="$1"; fi; shift ;;
  esac
done

if [ "$CMD" != "questionnaire" ] || [ -z "$FILE" ]; then
  echo "usage: vendorvet.sh questionnaire <file> [--format json]" >&2
  exit 1
fi
if [ ! -f "$FILE" ]; then
  echo "error: cannot read $FILE" >&2
  exit 1
fi

# Validate the data classification up front (jq null-mult would fail silently).
CLASS="$(jq -r '.data_classification // "internal"' "$FILE" 2>/dev/null || echo internal)"
case "$CLASS" in
  public|internal|confidential|restricted) ;;
  *) echo "error: data_classification must be public|internal|confidential|restricted" >&2; exit 1 ;;
esac

# The catalog + scoring, expressed entirely in jq. Keys/weights/polarity and the
# class multipliers are identical to vendorvet/core.py.
JQ_PROG='
def catalog: {
  "soc2_type2":[10,true],"iso27001":[6,true],"encryption_at_rest":[9,true],
  "encryption_in_transit":[9,true],"mfa_enforced":[8,true],"pentest_annual":[7,true],
  "incident_response_plan":[6,true],"breach_notification_sla":[7,true],
  "subprocessor_list":[4,true],"data_retention_policy":[5,true],
  "vuln_mgmt_program":[6,true],"employee_security_training":[4,true],
  "shares_data_with_third_parties":[8,false],"prior_breach_24mo":[9,false]
};
def mult($c): {"public":0.6,"internal":0.85,"confidential":1.1,"restricted":1.35}[$c];
def tier($s): if $s>=70 then "critical" elif $s>=45 then "high" elif $s>=20 then "moderate" else "low" end;
def r2($x): (($x*100)|round)/100;

. as $doc
| ($doc.vendor // "unknown vendor") as $vendor
| ($doc.data_classification // "internal") as $class
| (mult($class)) as $m
| ($doc.answers) as $ans
| (catalog | to_entries) as $cat
| ([$cat[].value[0]] | add) as $tw
| ([ $cat[]
     | .key as $k | .value[0] as $w | .value[1] as $safe
     | if ($ans|has($k))
       then (if (($ans[$k]) == $safe) then 0 else $w end)
       else ($w/2) end ] | add) as $pen
| ([ $cat[] | .key as $k | select($ans|has($k)) ] | length) as $answered
| (r2(100*$pen/$tw)) as $raw
| ([r2($raw*$m),100]|min) as $residual
| {vendor:$vendor, data_classification:$class, raw_score:$raw,
   inherent_multiplier:$m, residual_score:$residual, tier:tier($residual),
   answered:$answered, total_controls:($cat|length)}
'

RESULT="$(jq -e "$JQ_PROG" "$FILE" 2>/dev/null)" || {
  echo "error: failed to score $FILE" >&2
  exit 1
}

TIER="$(printf '%s' "$RESULT" | jq -r .tier)"

if [ "$FORMAT" = "json" ]; then
  printf '%s\n' "$RESULT"
else
  printf 'Vendor:           %s\n' "$(printf '%s' "$RESULT" | jq -r .vendor)"
  printf 'Data class:       %s (x%s)\n' \
    "$(printf '%s' "$RESULT" | jq -r .data_classification)" \
    "$(printf '%s' "$RESULT" | jq -r .inherent_multiplier)"
  printf 'Controls answered:%s/%s\n' \
    "$(printf '%s' "$RESULT" | jq -r .answered)" \
    "$(printf '%s' "$RESULT" | jq -r .total_controls)"
  printf 'Residual score:   %s/100\n' "$(printf '%s' "$RESULT" | jq -r .residual_score)"
  printf 'Risk tier:        %s\n' "$TIER"
fi

case "$TIER" in
  high|critical) exit 2 ;;
  *) exit 0 ;;
esac
