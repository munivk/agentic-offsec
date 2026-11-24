"""
Live, human-readable view of the agent's decisions, read from the audit log as it is written.
Read-only: it never writes to the log or talks to the agent. Used for the demo video.

    python watch_audit.py                 # wait for the next run's log in audit/, follow it
    python watch_audit.py <log.jsonl>     # replay a finished log (e.g. evidence_clean/...)

Run it in a second terminal pane next to run_agent.py or run_gate_live.py.
"""
import glob
import json
import os
import sys
import time

DIM, BOLD, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[2m", "\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m")
LEVEL_COLOR = {"low": GREEN, "medium": YELLOW, "high": RED}


def short(text, n=160):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def render(r):
    e, t = r["event"], r["ts"][11:19]
    call = f"call {r['call']}" if "call" in r else ""
    if e == "run_start":
        pol = f"  policy {r['policy_sha256'][:12]}" if r.get("policy_sha256") else ""
        return f"{BOLD}{t}  RUN START{RESET}  target {r['target']}  model {r['model']}{pol}"
    if e == "agent_reasoning":
        return f"{t}  {CYAN}AGENT THINKS{RESET}  {short(r['text'])}"
    if e == "tool_call":
        return f"{t}  {BOLD}{call:>7}  PROPOSES{RESET}  {r['tool']} {r['input']}"
    if e == "impact_gate":
        c = LEVEL_COLOR.get(r["level"], "")
        line = f"{t}  {call:>7}  {c}GATE {r['level'].upper()}{RESET}: {r['reason']} -> {BOLD}{r['decision']}{RESET}"
        if r.get("approver"):
            line += f"  (by {r['approver']}: \"{r.get('approver_reason')}\")"
        return line
    if e == "tool_result":
        s = r["summary"]
        bits = [f"status {s.get('status')}"]
        if s.get("http_status") is not None:
            bits.append(f"HTTP {s['http_status']}")
        if s.get("count") is not None:
            bits.append(f"{s['count']} findings")
        if s.get("partial"):
            bits.append("partial results kept")
        if s.get("template_ids"):
            bits.append("templates " + ", ".join(sorted(set(s["template_ids"]))[:5]))
        if s.get("exclusions_lifted"):
            bits.append(f"exclusions lifted {s['exclusions_lifted']}")
        return f"{t}  {call:>7}  RESULT  " + short("; ".join(bits), 200)
    if e == "consistency_check":
        bad = sorted({c["tag"] for c in r.get("contradictions", [])})
        tag = (f"{GREEN}consistent{RESET}" if r.get("consistent", not bad)
               else f"{YELLOW}flagged for review: {', '.join(bad)}{RESET}")
        return f"{t}  CHECK   report 'did not test' list vs tags actually run: {tag}"
    if e == "final_report":
        return f"{BOLD}{t}  REPORT WRITTEN{RESET}  (forced={r.get('forced')})"
    if e == "max_steps_reached":
        return f"{t}  {YELLOW}MAX STEPS REACHED{RESET}"
    return None  # llm_usage and anything else: not shown


def follow(path, live):
    print(f"{DIM}audit log: {path}{RESET}\n")
    with open(path) as f:
        while True:
            line = f.readline()
            if not line:
                if not live:
                    return
                time.sleep(0.5)
                continue
            r = json.loads(line)
            out = render(r)
            if out:
                print(out, flush=True)
            if live and r["event"] == "final_report":
                return


def main():
    if len(sys.argv) > 1:
        follow(sys.argv[1], live=False)
        return
    before = set(glob.glob("audit/audit_*.jsonl"))
    print(f"{DIM}waiting for a new run in audit/ ...{RESET}")
    while True:
        new = set(glob.glob("audit/audit_*.jsonl")) - before
        if new:
            follow(max(new, key=os.path.getmtime), live=True)
            return
        time.sleep(0.5)


if __name__ == "__main__":
    main()
