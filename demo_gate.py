"""
Deterministic demonstration that the impact gate fires on a high-risk action.

The agent, well-governed by its prompt, normally will not even propose an active
action. This shows what happens if one reaches the gate: it is scored high-risk,
the checkpoint denies it by policy (this demo never asks a person), it is logged,
and the tool refuses it as a second layer. Defense in depth.

Run: python demo_gate.py
"""
import os
from agent import risk, tools
from agent.audit import Audit


def policy_deny(name, inp, score):
    # Deterministic: this demo never asks a person. The live human checkpoint is run_gate_live.py.
    return False, "policy:auto-deny", "gate demo; high-risk actions denied by policy"

if os.path.exists("audit/gate_demo.jsonl"):
    os.remove("audit/gate_demo.jsonl")  # start clean (Audit refuses an existing file)
audit = Audit("audit/gate_demo.jsonl")
target = "http://localhost:3000"

for action in [{"tool": "run_nuclei", "input": {"tags": ["exposure"]}},
               {"tool": "run_nuclei", "input": {"tags": ["sqli"]}},
               {"tool": "run_nuclei", "input": {"tags": ["default-login"]}},
               {"tool": "run_nuclei", "input": {"severity": ["critical"]}}]:  # no tags
    name, inp = action["tool"], action["input"]
    score = risk.score_action(name, inp)
    print(f"\nProposed: {name} {inp}")
    print(f"  gate score: {score['level'].upper()} ({score['reason']})")
    if score["level"] == "high":
        approved, who, why = policy_deny(name, inp, score)
        audit.log("impact_gate", tool=name, input=inp, level="high",
                  decision="approved" if approved else "denied", reason=score["reason"],
                  approver=who, approver_reason=why)
        print(f"  checkpoint: {'APPROVED' if approved else 'DENIED'} ({who})")
        # second layer: the tool refuses active tags without approval
        result = tools.run_nuclei(target, tags=inp.get("tags"), approved=False)
        print(f"  tool layer: {result['status']} ({result.get('note','')[:55]})")
    else:
        audit.log("impact_gate", tool=name, input=inp, level="low", decision="auto",
                  reason=score["reason"])
        print("  auto-run (low risk)")

print(f"\nGate decisions logged to {audit.path}; verify with: python verify_audit.py {audit.path}")
