"""
Scoped scripted baseline: chunked Nuclei + rule-based triage, NO LLM.

This is the FAIR control for the agent. The naive baseline (baseline.py) throws
the whole passive tag set at Nuclei in one scan and times out inside the budget,
returning nothing. A competent engineer who knows that would script the obvious
fix: split the tags into small chunks so each scan completes, aggregate, then
triage with fixed rules. That is exactly what this does, with no model.

So the only thing left for the agent to beat is JUDGMENT: adaptive confirmation
fetches, severity reasoning, and honest uncertainty labeling. This baseline
isolates that. Same scanner, same tags, same timeout per scan as the agent.

Usage: python baseline_scoped.py
"""
import time
import json
from agent.tools import run_nuclei

# Fixed chunks covering the full passive tag set, <=3 tags each so a scan can
# complete. This decomposition is scripted and reproducible: it does not depend
# on a model choosing it at run time.
CHUNKS = [
    ["exposure", "misconfig", "panel"],
    ["api", "swagger", "config"],
    ["headers", "cors", "ssl"],
    ["tech", "backup"],
]
PER_SCAN_TIMEOUT = 300  # same per-scan budget the agent's tool call uses

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
NOISE_TEMPLATES = {"http-missing-security-headers"}  # high-volume, low-value


def main():
    target = "http://localhost:3000"
    started = time.time()
    findings = []
    timed_out_chunks = []
    for chunk in CHUNKS:
        res = run_nuclei(target, tags=chunk, timeout_s=PER_SCAN_TIMEOUT)
        if res.get("status") == "timeout":
            timed_out_chunks.append(chunk)
        findings.extend(res.get("findings", []))

    # rule-based triage: dedupe by template-id, drop known header noise, sort by severity
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
        "mode": "scoped_scripted_baseline",
        "chunks": CHUNKS,
        "per_scan_timeout_s": PER_SCAN_TIMEOUT,
        "duration_s": round(time.time() - started, 1),
        "timed_out_chunks": timed_out_chunks,
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
    with open("reports/baseline_scoped_result.json", "w") as fp:
        json.dump(out, fp, indent=2)


if __name__ == "__main__":
    main()
