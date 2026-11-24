"""
Print the impact-gate decisions from an audit log: every high-risk action, who decided,
why, and which exclusions an approval lifted. Read-only; used in the demo.

    python show_gate.py evidence_clean/audit_gate_live_<stamp>.jsonl
    python show_gate.py            # newest live-gate log
"""
import glob
import json
import os
import sys

path = sys.argv[1] if len(sys.argv) > 1 else max(
    glob.glob("evidence_clean/audit_gate_live_*.jsonl"), key=os.path.getmtime)
records = [json.loads(line) for line in open(path)]
print(f"Audit log: {path}\n")
for r in records:
    if r["event"] == "run_start":
        print(f"policy sha256: {r.get('policy_sha256', '(not logged)')}")
        if r.get("policy_levels"):
            print(f"policy levels: {r['policy_levels']}\n")
    if r["event"] == "impact_gate" and r["level"] == "high":
        print(f"call {r['call']}: {r['decision'].upper()} by {r.get('approver')}")
        print(f"  gate reason:     {r['reason']}")
        print(f"  approver reason: {r.get('approver_reason')}")
    if r["event"] == "tool_result" and r["summary"].get("exclusions_lifted"):
        s = r["summary"]
        print(f"call {r['call']}: ran, {s['count']} findings, "
              f"exclusions lifted: {s['exclusions_lifted']} (all others stayed excluded)")
