# Governed Agentic Triage for Offensive Security (PoC)

A proof of concept that puts an **AI agent on top of an open-source scanner
([Nuclei](https://github.com/projectdiscovery/nuclei))**. The agent decides what to scan,
judges what matters and writes the report. Every action it proposes is first scored by an
**impact gate**: low-risk actions run, medium-risk actions run and are flagged, and
high-risk actions stop until a named person approves or denies them. Every step goes into
a tamper-evident audit log.

Target: [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately
vulnerable web app, running locally in Docker as an authorized sandbox. The agent is
read-only by design.

**Demo video (2 parts, split because the end-to-end demo runs a little longer than usual):**
[part 1](https://www.loom.com/share/e933403b4cea47fba0cf47579e96f097) ·
[part 2](https://www.loom.com/share/5ff781ea0dfd44419c28c7e6480d08b7)

## Where to start

| If you want | Read |
|---|---|
| The one-page analysis | [`ANALYSIS.md`](ANALYSIS.md) |
| Full results, assumptions, findings from testing, limits | [`EVALUATION.md`](EVALUATION.md) |
| Test results: the raw evidence behind every number | [`evidence_clean/`](evidence_clean/) (file guide in `EVALUATION.md`; generated table: [`TABLE.md`](evidence_clean/TABLE.md)) |
| To run it yourself | [Step-by-step](#step-by-step-from-zero-to-a-verified-run) below |

## Results at a glance

3 scripted baseline runs vs 3 agent runs, one code version, one model (Claude Sonnet 4.6 on
AWS Bedrock), plus one live run where a human decided at the gate.

| | Scripted baseline (no model) | Agent |
|---|---|---|
| Found `/metrics` and Swagger | 3 of 3 runs | 3 of 3 runs, each confirmed by a read-only GET |
| Wall-clock per run | 7.4 min | 7.4 to 9.9 min |
| Model cost per run | $0 | $0.069 to $0.074 (estimate) |
| Output | 14 raw hits, 7 distinct, flat list | 4 to 5 ranked findings, each with a reason, an action and the `call N` that observed it |
| Severity of the two real findings | template defaults | MEDIUM in 3 of 3 runs for both |

- **Coverage is a tie.** The baseline is as good, faster and free. The agent adds
  confirmation, explanation, recommended actions, citations and a "what I did not test"
  list. Whether that saves analyst time is not yet measured.
- **The gate, live.** A human denied a SQL injection scan (not run, reported as untested)
  and approved a default-credentials scan (only that one exclusion was lifted; it found
  nothing). The log records who decided and why. Approval is not validation: the approved
  check could not test this app's login.
- **What did not work.** An automated report-vs-log consistency check (every flag was a
  false positive), following new leads, and scan sizing (one scan per run hit the 5-minute
  limit; its partial findings were kept and reported as partial).

Every agent audit log records the code fingerprint (`python fingerprint.py`), the policy
hash and the model, so each number is tied to the exact code and rules that produced it.

---

## Why this design

Autonomous offensive-security products compete on capability and autonomy. Several have
real safety controls (XBOW, the closest, checks every proposed action and blocks unsafe
ones under its own rules). But none of the eight products examined lets **the organization
running the tool** set the rules: a graded risk decision for each action, a pause for a
named person on the risky ones, and a record of who decided and why. For a regulated
organization (finance, healthcare, government), that control is what blocks adoption, not
a lack of autonomy.

The clearest and safest place for a model is **triage, decision and reporting**. Scanning
is already done well by deterministic tools, and live exploitation is the risky, unreliable
part. So this PoC keeps Nuclei as the engine and puts the agent at the triage layer.

**The thesis:** let the model make the decisions, inside a fence and in front of a camera.
The fence is the impact gate and read-only tools. The camera is the hash-chained audit log.

---

## How it works

### The tool it extends: Nuclei

Nuclei checks a target against a community library of YAML templates (11,835 web templates
in v10.5.2), each a request plus a pattern that signals a match: exposed files and panels,
misconfigurations, known CVEs, default logins. It is fast and deterministic, and security
engineers, pentesters and bug-bounty hunters use it as an early step to find known exposures
across many targets. What it does not do is reason: it returns a flat list with duplicate
noise, cannot decide what to scan next, and does not explain a finding or recommend an
action. Those gaps are judgment work, which is where the agent comes in.

### The two agentic capabilities added

1. **Agent-driven scoping and triage.** The agent chooses focused scans, confirms findings
   with read-only fetches, ranks and explains them, and writes a report in which every
   finding cites the tool call that observed it.
2. **Impact-gated autonomy.** Every action the agent proposes is scored against the
   organization's policy before it runs, and high-risk actions pause for a named person.
   This is the control the market research found missing.

### What the agent does

Given a goal ("assess this target"), it loops for up to 8 model turns:

1. **Plan.** Choose the next focused scan by Nuclei tags, based on what it has found.
2. **Act.** Propose the action. The impact gate scores it, then it runs, runs flagged, or
   waits for a human.
3. **Triage.** Separate real risks from noise and explain each in plain English.
4. **Confirm.** Optionally fetch one page (read-only GET) to verify a finding.
5. **Report.** A prioritized report with confidence levels, recommended human actions,
   discarded noise, and an explicit "what I did not test" section. If the turns run out,
   the agent is forced to write the report.

The model proposes every action. The code scores it, enforces the policy, runs only what is
permitted and records everything.

### Architecture

```
  Claude Sonnet 4.6 on AWS Bedrock    agent/bedrock.py   the "brain": proposes the next action
                |
                v
  Agent loop                          agent/agent.py     plan, act, observe, report
                |
                v
  Impact gate                         agent/risk.py      scores each action low / medium / high
                |                     policy.toml        low: run | medium: run and flag
                |                                        high: pause for a named human (or deny)
                v
  Tools (read-only)                   agent/tools.py     run_nuclei (scoped scan), fetch_url (GET)
                |                                        host allowlist enforced here
                v
  Nuclei  -->  OWASP Juice Shop       Docker, localhost:3000

  Every step above  -->  agent/audit.py   hash-chained JSONL audit log
```

The loop is hand-written, with no agent framework, so the decision logic stays visible.
`bedrock.py` uses the Bedrock Converse API, so the model can be swapped without touching the
agent.

### Guardrails

- **The organization's policy, in a file.** `policy.toml` holds the allowed hosts, the
  passive and active tag lists, the sensitive paths, and what each risk level does (`run`,
  `run_and_flag`, `ask_human`, `deny`). Its header calls it "the buyer's policy": the rules
  of the organization that runs the tool, not of the vendor that makes it. The security team
  changes it without touching code; in production it would come from the institution's
  policy engine. It can tighten the gate but not loosen it below a floor: at start-up,
  unknown values, overlapping tag lists, or `high` set to anything but `ask_human` or `deny`
  stop the program. The policy's SHA-256 hash is in every audit log.
- **Impact gate (action allowlist).** `run_nuclei` must be given tags and only runs passive,
  detection tags. A scan with no tags would run the whole library, so it scores high and the
  tool refuses it even if approved. Every active tag (`sqli`, `xss`, `default-login`,
  `auth-bypass`, `takeover`, ...) scores high: in an automated run it is denied and logged;
  in an interactive run it pauses for a person. The same active list is always excluded from
  every scan (`-etags`), so the score and the exclusion cannot disagree. An approval lifts
  only the approved tag, and the log records who approved and why. Fetching a sensitive path
  (`/metrics`, `/ftp`, `/admin`, backups) scores medium: it runs, is flagged in the log, and
  is listed under "Flagged for human review" at the end of the report (added by the code,
  not the model).
- **Host allowlist.** Tools refuse any host except `localhost:3000` / `127.0.0.1:3000`. The
  model cannot change the host; what it controls is `tags`, `severity` and `path`, which is
  why the impact gate is the control that matters.
- **Honest tool failure.** A timed-out scan returns `status: "timeout", partial: true` with
  the note that absence of a finding is not evidence of absence. Findings are read from
  Nuclei's output stream as they arrive, so a scan cut off at its limit keeps what it found.
- **Evidence rule.** Every tool call has a number, and every finding must cite the `call N`
  that observed it. Anything unobserved goes under "Hypotheses for a human".
- **Tamper-evident audit.** Each run writes its own hash-chained JSONL log, and
  `verify_audit.py` detects an edited record. Someone with write access could still rewrite
  the whole chain or drop the last records; production anchors the head hash externally
  (KMS-signed, or S3 Object Lock).
- **Named approver.** The approver is `APPROVER`, or the OS user if unset. That is
  self-declared; production binds it to SSO identity and a change ticket.

---

## Step-by-step: from zero to a verified run

Every step has a check. Do not move on until the check passes.

### Step 1. Install the prerequisites (once)

| Tool | Install (macOS) | Check |
|---|---|---|
| Python 3.11+ | `brew install python` | `python3 --version` |
| Docker Desktop | [docker.com](https://www.docker.com/products/docker-desktop/), then start it | `docker info` prints a server version |
| Nuclei | `brew install nuclei` | `nuclei -version` |
| AWS CLI | `brew install awscli` | `aws --version` |

Python 3.11+ is needed because the policy file is read with the standard library's `tomllib`.
The evaluation used Nuclei v3.11.1 with templates v10.5.2. Newer versions work, but finding
counts may differ.

### Step 2. Get the code and create the Python environment

```bash
git clone https://github.com/munivk/agentic-offsec.git
cd agentic-offsec
python3 -m venv .venv
source .venv/bin/activate         # your prompt now starts with (.venv)
pip install -r requirements.txt
```

Check: `which python` prints `<this folder>/.venv/bin/python`.

> Every `python ...` command below assumes the venv is active. Each new terminal needs
> `source .venv/bin/activate` again. Without it, macOS has no `python` command, and a bare
> `python3` is the system interpreter without `boto3`. `.venv/bin/python <script>` always
> works. The venv stores absolute paths: if you move the folder, delete `.venv` and redo
> this step.

### Step 3. AWS credentials for Bedrock

The model is Claude on AWS Bedrock. The code uses the standard AWS credential chain, or the
profile named in `AWS_PROFILE`. Use a least-privilege identity that can only invoke Bedrock.

```bash
aws configure                     # or: aws sso login, or export temporary keys
# optional overrides:
export AWS_PROFILE=<profile>      # default: standard credential chain
export AWS_REGION=us-east-1       # default
export BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6   # default; any Bedrock model id works
```

Check: `aws sts get-caller-identity` prints an account and ARN. An `InvalidClientTokenId` or
`ExpiredToken` error means the credentials need refreshing. The account also needs Bedrock
model access enabled for the model above.

### Step 4. Start the authorized sandbox target

```bash
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
```

Check (wait 10 to 30 s; Juice Shop boots slowly):

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000    # expect 200
```

`000` means nothing is answering yet: wait and retry, or look at `docker logs juiceshop` for
"Server listening on port 3000". If the container already exists, use `docker start juiceshop`.

### Step 5. Smoke test the guardrails (no model, no AWS, seconds)

```bash
python demo_gate.py
python verify_audit.py audit/gate_demo.jsonl
```

Check: the demo shows `sqli`, `default-login` and an untagged scan scored HIGH and refused,
and `verify_audit.py` reports the chain intact.

### Step 6. Run the agent once (about 10 minutes)

```bash
python run_agent.py
```

Outputs:
- `reports/agent_report.md`: the prioritized report
- `audit/audit_<timestamp>.jsonl`: the full decision trail
- `scans/nuclei_latest.jsonl`: raw scanner output from the last pass

Check: `python verify_audit.py audit/audit_<timestamp>.jsonl` reports the chain intact.

### Step 7. Reproduce the evaluation (about 50 minutes)

```bash
bash run_clean.sh                 # 3 scripted baselines + 3 agent runs + gate demo
python evidence_table.py          # writes evidence_clean/TABLE.md
```

`run_clean.sh` refuses to start if the AWS credentials are invalid, if the `juiceshop`
container does not exist (set `JUICESHOP_CONTAINER` for another name), or if another scan is
already running. It restarts Juice Shop before every run, so each run sees a fresh target.

Check: `evidence_clean/verify.out` shows every chain intact, and `TABLE.md` reports one code
fingerprint across the agent logs.

### Step 8. The live impact gate (interactive, two terminals, about 12 minutes)

This is the one run where the agent may *request* active checks and a human decides. Open two
terminals, `cd` into this folder and run `source .venv/bin/activate` in **both**. Then run one
command in each:

```bash
# Terminal 1, start first: waits for the next run's log in audit/, then follows it live
python watch_audit.py

# Terminal 2: the agent. Answer each approval prompt here (y/N plus a reason).
APPROVER=<your name or role> python run_gate_live.py
```

To exercise the gate, deny one high-risk request and approve another. The log records who
decided, why, and exactly which exclusions an approval lifted. The log and report are copied
to `evidence_clean/` automatically.

Check, afterwards:

```bash
python show_gate.py                                   # every high-risk decision, who, why
python verify_audit.py evidence_clean/audit_gate_live_<stamp>.jsonl
```

### Replay any finished run

```bash
python watch_audit.py evidence_clean/audit_1.jsonl    # readable view of a finished log
python fingerprint.py                                 # compare with CODE_SHA256 in evidence_clean/_meta.txt
```

---

## Known limitations

- **Coverage belongs to the baseline, not the agent.** The agent's job is triage; run the
  deterministic baseline for guaranteed coverage.
- **Scan sizing.** The prompt asks for at most 3 tags per scan, but a scan can still hit the
  300 s limit. A timed-out scan keeps its partial findings and is reported as partial.
- **Nuclei's blind spots carry over.** It finds known exposures, CVEs and misconfigurations,
  not business-logic or auth flaws, which is most of what Juice Shop contains. The agent
  reports those areas as untested.
- **The agent confirms; it does not yet explore.** The decision space is small by design (13
  passive tags plus GETs), so this evaluation cannot separate agent planning from a script
  that runs the same tags in small batches. Following new leads needs a larger action space.
- **The consistency check is a heuristic.** It flagged all 3 evaluation runs and every flag
  was a false positive (`EVALUATION.md`, finding 6). Its output is not evidence.
- **Prompt injection.** `fetch_url` passes fetched page content into the model context; a
  hostile target could attempt injection through it. Fetched content should be wrapped as
  untrusted data.
- **Single target, single scanner, small run count.** PoC scope. Juice Shop is well known to
  the model, which flatters it; a custom or modified app is the better test.
- **The action allowlist trusts community template tags.** A template that does something
  active but is tagged only as passive would get through. Production would run an internally
  reviewed, pinned template list, not tag selection.
- **The risk score is a static rule table.** Production would add context such as asset
  criticality and what the agent has already found.

`evidence_development/` holds runs from development on earlier code. They back qualitative
findings only and are not part of the evaluation.

## Scope

- Pre-production and explicitly authorized test targets only. In this PoC the host
  allowlist in `policy.toml` permits only the local Juice Shop sandbox.
- Read-only by design: detection scans and GETs. Active checks run only when a named human
  approves them at the impact gate.

---

## Repository layout

```
agentic-offsec/
  README.md             this file
  ANALYSIS.md           one-page analysis
  EVALUATION.md         full evaluation, findings from testing, limits
  requirements.txt
  policy.toml           the policy: hosts, tag lists, sensitive paths, level actions
  agent/
    bedrock.py          brain: Bedrock Converse wrapper
    tools.py            hands: run_nuclei, fetch_url (+ host allowlist)
    agent.py            the agent loop, system prompt, tool specs
    audit.py            hash-chained decision log
    risk.py             impact gate: scores each proposed action
  run_agent.py          entry point
  run_gate_live.py      interactive live gate run
  baseline.py           scripted control, no model
  baseline_scoped.py    scripted control in small tag batches, no model (not in the evaluation)
  demo_gate.py          deterministic gate demo, no model
  run_clean.sh          the evaluation batch
  evidence_table.py     builds the evidence table from the logs
  fingerprint.py        code fingerprint recorded in every run
  verify_audit.py       checks an audit log's hash chain
  show_gate.py          prints the gate decisions from a live-gate audit log
  watch_audit.py        live or replayed readable view of an audit log
  docs/architecture.svg production architecture sketch
  evidence_clean/       the evaluation: audit logs, reports, baselines, TABLE.md
  evidence_development/ development runs behind the qualitative findings
  audit/ reports/ scans/  run outputs (gitignored)
```

> **Authorization:** This tool is restricted by code to a local sandbox you control.
> Do not point it at systems you are not explicitly authorized to test.
