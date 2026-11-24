# Analysis (one page)

Governed triage agent on Nuclei vs a scripted baseline, OWASP Juice Shop sandbox. One code
version (fingerprint in every audit log), one model (Claude Sonnet 4.6), 3 runs each, plus one
live gate run. Full table, findings and limits: `EVALUATION.md`. Raw evidence: `evidence_clean/`.

| | Baseline (no model) | Agent |
|---|---|---|
| Found `/metrics` + Swagger | 3 of 3 | 3 of 3, each confirmed by a GET |
| Wall-clock | 7.4 min | 7.4 to 9.9 min |
| Cost per run | $0 | $0.069 to $0.074 (estimate) |
| Output | 14 raw hits, 7 distinct, flat list | 4 to 5 ranked findings, each citing the call that observed it |

**What worked.** Triage. Every run rated `/metrics` and Swagger MEDIUM, confirmed both with a
read-only fetch, collapsed header noise into one finding, gave a reason and a recommended
action for each item, and listed what it did not test. Every finding cited a logged tool call,
and every cited scan's logged template IDs include the finding. Each run's first scan timed
out and still returned its partial findings, reported as partial. All audit hash chains verify.

**What failed.** Coverage is no better than the baseline, and the agent is usually slower. A
scan still hit the 300 s limit in every run, even with the prompt asking for at most 3 tags per
scan. The automated consistency check (report claims vs logged actions) flagged all 3 runs,
and every flag was a false positive. It is not usable yet.

**Where human intervention was required.** Only at the impact gate. In the automated runs the
agent never asked for a high-risk action, so no human was needed and the gate never fired.
In the live session, where the agent was allowed to ask, a human denied a SQL injection scan
and approved a default-credentials scan. Only that one exclusion was lifted, and the log
records who decided and why. The agent did not retry the denied action and reported it as
untested. The approved check found nothing, because no default-login template targets this
app's login, yet the summary said "No default credentials were found." Approval is not
validation: the gate decides whether an action is safe, not whether it can answer the question.
The approver identity is self-declared here; production binds it to SSO identity and a ticket.

**False positives, false negatives, reliability.**
- **False positives.** No uncited findings. But inside cited findings, every report named which security headers
  are "likely" missing from memory (the scan reported only a count), and the live report said
  two Swagger paths returned 200 when one was fetched. The audit log keeps template IDs, not
  matched URLs, so citations are checkable at template level only. Next steps: log matched
  URLs, and apply the citation rule to every claim, including negatives.
- **Reliability.** Testing found three gate and tool defects, all fixed before the evaluation: a timed-out
  scan lost its findings, an auto-approved scan dropped the intrusive-template exclusions, and
  an untagged scan scored low. `demo_gate.py` shows the untagged case refused.
- **False negatives.** All 3 runs saw a `cleanupFtpFolder` task in `/metrics` and none
  checked `/ftp`, a known exposure on this target: the agent confirmed what the scanner found
  but did not follow new leads. And the live report's "No default credentials were found"
  is a false negative waiting to happen (see above). Each run did pass the AI token counters
  in `/metrics` to a human as an untested surface. With 13 passive tags and GETs, this
  evaluation cannot separate agent planning from a script that runs the same tags in small
  batches.
- **Sample.** Juice Shop is a memorized target, so it flatters the model. Three runs is a
  behavior check, not a reliability result.

**Did the agentic layer improve the workflow?** It added something the baseline lacks, but its
value is not yet measured. The baseline already ranks `/metrics` first and dedupes header
noise. The agent adds read-only confirmation, explanations, recommended actions, call
citations and a coverage statement, for about seven cents a run. Whether that saves analyst
time is the next measurement. Not at the coverage layer, where the deterministic baseline is
as good, faster and free. So the design is deterministic coverage with agentic judgment,
inside a per-action gate.
