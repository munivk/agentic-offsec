"""
The agent loop: a hand-written plan -> score -> act -> observe loop (no framework).

The loop is hand-written so the decision logic stays visible and auditable. The
model is given a goal and two tools. Before ANY action runs, the impact gate
(risk.py) scores it; high-risk actions pause for a human. Every reasoning step,
gate decision, and tool result is written to a tamper-evident audit log. After the
report is produced, a consistency check compares what the agent SAID it did not do
against what the audit log shows it actually did.
"""
import getpass
import json
import os
import sys
from . import bedrock, tools, risk
from .audit import Audit

TOOLS = [
    {"toolSpec": {
        "name": "run_nuclei",
        "description": (
            "Run a SCOPED, detection-only Nuclei scan against the authorized target. "
            "Choose passive tags to focus the scan. Use at most 3 tags per call: broad scans "
            "with many tags time out. Allowed tags: exposure, misconfig, "
            "tech, api, swagger, config, backup, headers, cors, ssl, panel. The scan is "
            "read-only and intrusive templates are excluded. If a result has "
            "status 'timeout', the scan did not finish and absence of findings is NOT "
            "evidence of absence: retry with fewer tags or report that area as untested."
        ),
        "inputSchema": {"json": {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"},
                         "description": "Passive tags from the allowed list above."},
                "severity": {"type": "array", "items": {"type": "string"},
                             "description": "Severities: info, low, medium, high, critical"},
            },
            "required": ["tags"],
        }},
    }},
    {"toolSpec": {
        "name": "fetch_url",
        "description": (
            "HTTP GET a single path on the authorized target to CONFIRM an exposure. "
            "Read-only, does not follow redirects. E.g. fetch /metrics or "
            "/api-docs/swagger.json after a scan finding."
        ),
        "inputSchema": {"json": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path, e.g. /metrics"}},
            "required": ["path"],
        }},
    }},
]

SYSTEM = [{"text": (
    "You are a governed offensive-security triage agent in an AUTHORIZED sandbox. "
    "Assess one approved target and produce a prioritized, honest report for a human.\n\n"
    "RULES:\n"
    "1. Only act on the target given to you.\n"
    "2. You are detection-only. You may run passive scans and GET pages. You must not "
    "attempt to exploit, inject payloads, or log in. Those actions are gated: if you "
    "request one, a human must approve it, and they will usually deny it. Flag anything "
    "needing exploitation for a human instead of attempting it.\n"
    "3. A scan result with status 'timeout' did NOT finish. Do not treat it as 'nothing "
    "found'. Retry with fewer tags, or report that area as untested.\n"
    "4. Triage honestly: separate real risks from noise, and label uncertainty.\n"
    "5. BUDGET: about 8 actions. Leave room to write the report.\n\n"
    "FINAL REPORT: start directly with the posture summary, no preamble (do not write "
    "'Let me compile the report' or similar). Plain text, no emoji. Every finding must cite the "
    "tool call that observed it as 'call N', using the 'call' number in that tool result; a claim with no observation goes under "
    "'Hypotheses for a human', not 'Findings'. One-line posture summary; prioritized findings "
    "(severity, what, why it matters, confidence, recommended human action); noise "
    "discarded; and an explicit 'What I did NOT test' list that MUST match your actual "
    "actions."
)}]


def default_approver(tool_name, inp, score):
    """
    Human checkpoint. Returns (approved, approver, reason) so the audit log records
    WHO decided and WHY, not just the decision.
    Interactive: ask a human. Non-interactive: deny high-risk by policy (fail safe).
    """
    if sys.stdin.isatty():
        print(f"\n[IMPACT GATE] high-risk action requested: {tool_name} {inp}")
        print(f"  gate reason: {score['reason']}")
        ans = input("  approve this action? [y/N] ").strip().lower()
        why = input("  reason for your decision: ").strip() or "(no reason given)"
        who = os.environ.get("APPROVER") or getpass.getuser()
        return ans in ("y", "yes"), f"human:{who}", why
    return False, "policy:auto-deny", "non-interactive run; high-risk actions denied by policy"


def consistency_check(report_text, ran_tags):
    """Compare the report's 'did not test' claims against tags actually run."""
    low = report_text.lower()
    contradictions = []
    for tag in sorted(ran_tags):
        if tag in low:
            # crude but effective: the tag was run; did the report deny testing it?
            for phrase in ("did not", "didn't", "not test", "not attempt", "no "):
                idx = low.find(phrase)
                while idx != -1:
                    window = low[idx: idx + 80]
                    if tag in window:
                        contradictions.append({"tag": tag, "claim_context": window.strip()})
                        break
                    idx = low.find(phrase, idx + 1)
    return {"ran_tags": sorted(ran_tags), "contradictions": contradictions,
            "consistent": not contradictions}


def flagged_from_log(path):
    """The actions the gate flagged, read back from the audit file itself."""
    inputs, out = {}, []
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            if r["event"] == "tool_call":
                inputs[r["call"]] = (r["tool"], r["input"])
            elif r["event"] == "impact_gate" and r.get("decision") == "auto-flagged":
                tool, inp = inputs.get(r["call"], (r["tool"], {}))
                out.append(f"call {r['call']}: {tool} {inp} ({r['reason']})")
    return out


def _summarize(result):
    if "findings" in result:
        return {"status": result.get("status"), "count": result.get("count"),
                "partial": result.get("partial", False),
                "severities": sorted({f.get("severity") for f in result["findings"]}),
                "template_ids": sorted({f.get("template_id") for f in result["findings"]}),
                "exclusions_lifted": result.get("exclusions_lifted", [])}
    return {"status": result.get("status"), "url": result.get("url"),
            "http_status": result.get("http_status")}


def run(target, goal, max_steps=8, audit_path=None, approver=default_approver, meta=None):
    client = bedrock.make_client()
    audit = Audit(audit_path)
    audit.log("run_start", target=target, goal=goal, model=bedrock.MODEL_ID, meta=meta or {},
              policy_sha256=risk.POLICY_SHA256, policy_levels=risk.LEVEL_ACTIONS)

    messages = [{"role": "user", "content": [{"text": goal}]}]
    ran_tags = set()
    call_no = 0  # global tool-call number: what reports cite, and what the audit logs

    def finish(final, step, forced=False):
        check = consistency_check(final, ran_tags)  # on the model's own words only
        flagged = flagged_from_log(audit.path)      # read back from the log, not from memory
        if flagged:
            final += ("\n\nFLAGGED FOR HUMAN REVIEW (ran automatically, flagged by policy; "
                      "read back from the audit log, not written by the model):\n"
                      + "\n".join(f"- {line}" for line in flagged))
        audit.log("consistency_check", step=step, **check)
        audit.log("final_report", step=step, forced=forced, text=final)
        return final, audit.path

    for step in range(max_steps):
        resp = bedrock.converse(client, messages, SYSTEM, tools=TOOLS)
        audit.log("llm_usage", step=step, usage=resp.get("usage"))
        msg = resp["output"]["message"]
        messages.append(msg)
        stop = resp["stopReason"]

        for block in msg["content"]:
            if "text" in block and block["text"].strip():
                audit.log("agent_reasoning", step=step, text=block["text"])

        if stop != "tool_use":
            return finish("".join(b.get("text", "") for b in msg["content"]), step)

        tool_results = []
        for block in msg["content"]:
            if "toolUse" not in block:
                continue
            tu = block["toolUse"]
            name, inp, tid = tu["name"], tu.get("input", {}), tu["toolUseId"]
            call_no += 1
            audit.log("tool_call", step=step, call=call_no, tool=name, input=inp)

            # IMPACT GATE: score every action before it runs; policy.toml says what each level does.
            score = risk.score_action(name, inp)
            action = risk.LEVEL_ACTIONS[score["level"]]  # validated at load
            approved = False  # True ONLY when a named human says yes
            if action in ("ask_human", "deny"):
                if action == "ask_human":
                    approved, approver_id, approver_reason = approver(name, inp, score)
                else:
                    approver_id, approver_reason = "policy:deny", "policy denies this level"
                audit.log("impact_gate", step=step, call=call_no, tool=name, level=score["level"],
                          reason=score["reason"], decision="approved" if approved else "denied",
                          approver=approver_id, approver_reason=approver_reason)
                if not approved:
                    result = {"status": "denied_by_gate", "count": None, "findings": [],
                              "note": f"denied at the impact gate ({approver_id}); not run"}
                    result = {"call": call_no, **result}
                    audit.log("tool_result", step=step, call=call_no, tool=name, summary=_summarize(result))
                    tool_results.append({"toolResult": {"toolUseId": tid,
                                                        "content": [{"json": result}]}})
                    continue
            else:
                # "run" or "run_and_flag": run, log the real level; flagged ones go in the report
                flag = action == "run_and_flag"
                audit.log("impact_gate", step=step, call=call_no, tool=name, level=score["level"],
                          reason=score["reason"], decision="auto-flagged" if flag else "auto")

            if name == "run_nuclei":
                result = tools.run_nuclei(target, tags=inp.get("tags"),
                                          severity=inp.get("severity"), approved=approved)
                if result.get("status") in ("ok", "timeout"):
                    ran_tags.update(t.lower() for t in (inp.get("tags") or []))
            elif name == "fetch_url":
                result = tools.fetch_url(target, path=inp.get("path", "/"))
            else:
                result = {"status": "error", "error": f"unknown tool {name}"}

            result = {"call": call_no, **result}
            audit.log("tool_result", step=step, call=call_no, tool=name, summary=_summarize(result))
            tool_results.append({"toolResult": {"toolUseId": tid, "content": [{"json": result}]}})

        messages.append({"role": "user", "content": tool_results})

    # Budget exhausted: force a final report with tools off.
    audit.log("max_steps_reached", steps=max_steps)
    messages.append({"role": "user", "content": [{"text": (
        "You have used your full action budget. Do NOT call any more tools. Write the "
        "FINAL REPORT now from what you have, in the specified format."
    )}]})
    resp = bedrock.converse(client, messages, SYSTEM, tools=None)
    audit.log("llm_usage", step=max_steps, usage=resp.get("usage"))
    return finish("".join(b.get("text", "") for b in resp["output"]["message"]["content"]),
                  max_steps, forced=True)
