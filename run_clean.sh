#!/bin/bash
# Clean evaluation batch: 3 scripted baselines + 3 agent runs on ONE model and ONE code
# version, plus the deterministic gate demo. About 55 minutes.
#
# Rules this script enforces so the evidence is trustworthy:
#   - records the code fingerprint (python fingerprint.py) in evidence_clean/_meta.txt;
#     every agent audit log carries the same value, so evidence is tied to exact code
#   - refuses to run if another nuclei process is already hitting the target
#   - restarts Juice Shop before every run, so each run sees a fresh target
#   - unbuffered output, so a crash still leaves a readable log
#
# Usage: bash run_clean.sh    (Juice Shop container must exist; name via JUICESHOP_CONTAINER)
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python
DOCKER=${DOCKER:-docker}
JS=${JUICESHOP_CONTAINER:-juiceshop}

if pgrep -x nuclei >/dev/null || pgrep -f "run_agent.py|baseline.py|demo_gate.py" >/dev/null; then
  echo "Refusing: another scan or agent run is active and would skew the evidence."; exit 1
fi
"$DOCKER" inspect "$JS" >/dev/null 2>&1 || {
  echo "Refusing: no container named '$JS'. Start Juice Shop (README step 4) or set JUICESHOP_CONTAINER."; exit 1; }
$PY -c "from agent import bedrock; bedrock.boto3.Session(profile_name=bedrock.PROFILE).client('sts').get_caller_identity()" >/dev/null 2>&1 || {
  echo "Refusing: AWS credentials are not valid (check: aws sts get-caller-identity)."; exit 1; }

fresh_target() {
  "$DOCKER" restart "$JS" >/dev/null
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000)" = 200 ] && return 0
    sleep 2
  done
  echo "Juice Shop did not come back"; exit 1
}

rm -rf evidence_clean && mkdir -p evidence_clean
{
  echo "MODEL: $($PY -c 'from agent import bedrock; print(bedrock.MODEL_ID)')"
  echo "CODE_SHA256: $($PY fingerprint.py)"
  echo "NUCLEI: $(nuclei -version 2>&1 | grep -o 'v[0-9.]*' | head -1)"
  echo "TEMPLATES: $(nuclei -templates-version 2>&1 | grep -o 'v[0-9.]*' | head -1)"
  echo "STARTED: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > evidence_clean/_meta.txt

for i in 1 2 3; do
  echo "=== BASELINE $i ==="; fresh_target
  $PY -u baseline.py > evidence_clean/baseline_$i.out 2>&1
  cp reports/baseline_result.json evidence_clean/baseline_$i.json
done
for i in 1 2 3; do
  echo "=== AGENT $i ==="; fresh_target
  $PY -u run_agent.py > evidence_clean/agent_$i.out 2>&1
  cp reports/agent_report.md evidence_clean/report_$i.md
  cp "$(ls -t audit/audit_2*.jsonl | head -1)" evidence_clean/audit_$i.jsonl
done
echo "=== GATE DEMO ==="
$PY -u demo_gate.py > evidence_clean/gate_demo.out 2>&1
cp audit/gate_demo.jsonl evidence_clean/audit_gate_demo.jsonl
for f in evidence_clean/audit_*.jsonl; do
  $PY verify_audit.py "$f" >> evidence_clean/verify.out 2>&1
done
echo "FINISHED: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence_clean/_meta.txt
echo "=== CLEAN BATCH DONE ==="
