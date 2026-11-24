"""
Entry point. Run from the repo root:

    python run_agent.py

Prereqs: Juice Shop at http://localhost:3000, Nuclei installed, and AWS credentials with
Bedrock access (the standard AWS credential chain, or a profile named in AWS_PROFILE).

Records run metadata (tool versions, model, target) so a run is reproducible, and
writes a fresh tamper-evident audit log per run under audit/.
"""
import os
import subprocess
from agent.agent import run
from fingerprint import code_sha256

TARGET = os.environ.get("TARGET", "http://localhost:3000")

GOAL = os.environ.get("GOAL", (
    f"Assess the authorized sandbox target at {TARGET} for exposures and "
    "misconfigurations. Run focused, detection-only scans, triage what you find, "
    "confirm at most a couple of findings with a read-only page fetch, and produce a "
    "prioritized report for a human reviewer. Do not exploit anything."
))


import re


def _strip_preamble(text):
    """Drop any chatter and emoji before the report proper."""
    text = re.sub(r"[\U0001F000-\U0001FAFF☀-➿]", "", text)  # emoji
    text = re.sub(r"\s*[\u2014\u2013]\s*", " - ", text)  # em/en dashes -> plain hyphen
    lines = text.splitlines()
    for i, line in enumerate(lines):
        low = line.lower()
        if line.startswith(("#", "**")) or "posture" in low or "summary" in low:
            return "\n".join(lines[i:]).strip()
    return text.strip()


def _cmd(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        out = (p.stdout + p.stderr).strip()  # nuclei prints version to stderr
        # keep just the version-looking token if present
        for tok in out.replace("\n", " ").split():
            if tok.lstrip("v").replace(".", "").isdigit():
                return tok
        return out.splitlines()[-1] if out else "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def main():
    meta = {
        "nuclei_version": _cmd(["nuclei", "-version"]) or "unknown",
        "nuclei_templates_version": _cmd(["nuclei", "-templates-version"]) or "unknown",
        "target": TARGET,
        "aws_profile": os.environ.get("AWS_PROFILE", "(default credential chain)"),
        "code_sha256": code_sha256(),
    }
    print(f"[*] Target: {TARGET}")
    print("[*] Running governed triage agent (detection-only, impact-gated, audited)...\n")
    report, audit_path = run(TARGET, GOAL, meta=meta)

    report = _strip_preamble(report)
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/agent_report.md"
    with open(report_path, "w") as f:
        f.write(f"# Agent Report for {TARGET}\n\n{report}\n")

    print(report)
    print(f"\n[*] Report saved to {report_path}")
    print(f"[*] Audit trail (tamper-evident): {audit_path}")
    print(f"[*] Verify it with: python verify_audit.py {audit_path}")


if __name__ == "__main__":
    main()
