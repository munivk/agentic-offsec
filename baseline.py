"""
Scripted baseline: plain Nuclei + simple rule-based triage, NO LLM.

This is the control the agent is compared against: if the agent cannot beat it, the
agentic layer is not earning its cost.
It runs one comprehensive detection-only scan over the safe tag set, then triages
deterministically: dedupe by template-id, drop known header noise, sort by
severity. It has no model, so it costs nothing and is fully reproducible.

Usage: python baseline.py
"""
import time
import json
from agent.tools import run_nuclei
from agent.risk import PASSIVE_TAGS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
NOISE_TEMPLATES = {"http-missing-security-headers"}  # high-volume, low-value


def main():
    target = "http://localhost:3000"
    started = time.time()
    res = run_nuclei(target, tags=sorted(PASSIVE_TAGS), timeout_s=1500)
    findings = res.get("findings", [])

    # rule-based triage
    seen, deduped = set(), []
    for f in findings:
        tid = f.get("template_id")
        if tid in seen:
            continue
        seen.add(tid)
        deduped.append(f)
    prioritized = [f for f in deduped if f.get("template_id") not in NOISE_TEMPLATES]
    prioritized.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 5))

    out = {
        "mode": "scripted_baseline",
        "status": res.get("status"),
        "duration_s": round(time.time() - started, 1),
        "raw_count": len(findings),
        "deduped_count": len(deduped),
        "prioritized_count": len(prioritized),
        "noise_dropped": len(deduped) - len(prioritized),
        "found_metrics": any("/metrics" in (f.get("matched_at") or "") for f in findings),
        "found_swagger": any("swagger" in (f.get("template_id") or "") for f in findings),
        "prioritized": [{"template_id": f.get("template_id"),
                         "severity": f.get("severity"),
                         "matched_at": f.get("matched_at")} for f in prioritized],
        "cost_usd": 0.0,  # no model
    }
    print(json.dumps(out, indent=2))
    with open("reports/baseline_result.json", "w") as fp:
        json.dump(out, fp, indent=2)


if __name__ == "__main__":
    main()
