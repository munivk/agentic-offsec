# Development evidence (qualitative findings only)

These files come from runs made **while the tool was being built**, on earlier versions of the
code. They are **not** part of the evaluation (that is `evidence_clean/`, produced by
`run_clean.sh` on the final code), and no number in `ANALYSIS.md` or `EVALUATION.md` comes
from them. They are kept unedited because the findings in `EVALUATION.md` ("Findings from
testing") rest on them. Report text is raw model output.

## Runs behind specific findings

| Files | Run | What it shows |
|---|---|---|
| `report_misreport_run3.md` + `audit_misreport_run3.jsonl` | Before the action allowlist existed | The report says it "did not attempt SQL injection" or "default credentials". The audit log shows `xss, sqli, injection` and `default-login` scans. The agent's narrative contradicted its own log (finding 3). |
| `report_prior_knowledge.md` + `audit_prior_knowledge.jsonl` | Goal asked for SQL injection testing | The agent declined the SQLi request at the prompt level, then rated the login endpoint High from its memory of Juice Shop. Its only observation was an HTTP 500 (finding 5). |

The misreport audit log pre-dates the hash chain, so `verify_audit.py` does not apply to it.

## `excluded_runs/`: a first evaluation attempt, discarded

| Files | Why it was discarded |
|---|---|
| `baseline_1..3.*` | All three hit the time limit with **0 findings**. This is how the lost-partial-results defect was found (finding 1): Nuclei's file export is only written on a clean exit. |
| `agent_1.out`, `audit_1.jsonl`, `report_1.md` | Ran on uncommitted code. |
| `agent_2.out`, `audit_2.jsonl`, `report_2.md` | Overlapped with other scans on the same target, so timings are not comparable. `audit_20261122T161526Z.jsonl` is the same log under its original name. |
| `agent_3.out` (empty), `audit_20261122T163837Z.jsonl` (8 records) | Stopped early because another session was scanning the same target. |

`_meta.txt` is the attempt's own metadata, as recorded at the time.
