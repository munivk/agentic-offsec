"""
The agent's "hands": the only actions it can take, and a hard safety backstop.

Design rule (governed autonomy): the hands are deliberately limited.
  1. run_nuclei  : run a SCOPED, rate-limited, DETECTION-ONLY vulnerability scan
  2. fetch_url   : HTTP GET a single page (read-only) to confirm a finding

Two layers of control live here, both enforced in code, not left to the model:
  - HOST allowlist: the agent can only touch the approved sandbox host.
  - ACTION allowlist: run_nuclei only runs passive/detection tags, and always
    excludes intrusive templates with -etags. A human approval (impact gate + human
    checkpoint) lifts only the specific active tags that were approved.
"""
import subprocess
import threading
import json
import os
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

from .risk import POLICY, PASSIVE_TAGS, ACTIVE_TAGS

# The agent may only ever act against these hosts (from policy.toml). The hard boundary.
ALLOWED_HOSTS = set(POLICY["allowed_hosts"])

# Every active tag is always excluded from a scan (defense in depth: even a passive pass
# will not fire a template that ALSO carries an active tag). Same list the gate scores.
EXCLUDE_TAGS = sorted(ACTIVE_TAGS)


def _check_target(target: str):
    netloc = urlparse(target).netloc or target
    if netloc not in ALLOWED_HOSTS:
        raise ValueError(
            f"Refused: target '{netloc}' is not in the host allowlist {sorted(ALLOWED_HOSTS)}"
        )


def run_nuclei(target, tags=None, severity=None, rate_limit=15,
               timeout_s=300, out_dir="scans", approved=False):
    """
    Run a focused, detection-only Nuclei scan.

    Returns a dict with an explicit STATUS. On timeout it reports status
    "timeout" with partial=True and a note, so the model can never read a
    timed-out scan as "nothing found" (the C1 bug this version fixes).
    """
    _check_target(target)
    tags = [t.lower() for t in (tags or [])]

    # No tags = the whole template library. Never run an unbounded scan, approved or not.
    if not tags:
        return {"status": "refused", "count": None, "findings": [],
                "note": "unbounded scan refused: choose 1 to 3 tags from the allowed list"}

    # ACTION allowlist: reject active tags unless a human approved this action.
    active = sorted(set(tags) & ACTIVE_TAGS)
    if active and not approved:
        return {"status": "refused", "count": None, "findings": [],
                "note": f"active tags {active} require human approval via the impact gate; not run"}
    unknown = sorted(set(tags) - PASSIVE_TAGS - ACTIVE_TAGS)
    if unknown:
        return {"status": "refused", "count": None, "findings": [],
                "note": f"tags {unknown} are not on the passive allowlist; choose from {sorted(PASSIVE_TAGS)}"}

    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "nuclei_latest.jsonl")
    if os.path.exists(out):
        os.remove(out)

    # Findings are read from stdout (-jsonl) line by line AS THEY ARRIVE. Nuclei's
    # file exports (-je / -jle) are only written when the scan exits cleanly, so a
    # killed scan loses everything; reading stdout keeps whatever was found before
    # the time limit. Each line is also copied to `out` as the raw scan record.
    # -duc: no template update check, so the template set cannot change mid-run.
    # -etags always runs. A human approval lifts ONLY the approved active tags from the
    # exclusion list; everything else (intrusive, dos, rce, ...) stays excluded.
    cmd = ["nuclei", "-u", target, "-rl", str(rate_limit), "-c", "10",
           "-timeout", "10", "-no-interactsh", "-silent", "-duc", "-jsonl"]
    lifted = sorted(set(tags) & set(EXCLUDE_TAGS)) if approved else []
    cmd += ["-etags", ",".join(t for t in EXCLUDE_TAGS if t not in lifted)]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if severity:
        cmd += ["-severity", ",".join(severity)]

    findings = []

    def _reader(stream, sink):
        for line in stream:
            line = line.strip()
            if not line:
                continue
            sink.write(line + "\n")
            sink.flush()
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    started = time.time()
    status, rc, timed_out = "ok", None, False
    with open(out, "w") as sink:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True)
        reader = threading.Thread(target=_reader, args=(proc.stdout, sink), daemon=True)
        reader.start()
        try:
            rc = proc.wait(timeout=timeout_s)
            if rc != 0:
                status = "error"
        except subprocess.TimeoutExpired:
            timed_out, status = True, "timeout"
            proc.kill()
            proc.wait()
        reader.join(timeout=5)
    duration = round(time.time() - started, 1)

    slim = [{
        "template_id": f.get("template-id"),
        "name": f.get("info", {}).get("name"),
        "severity": f.get("info", {}).get("severity"),
        "matched_at": f.get("matched-at") or f.get("host"),
        "tags": f.get("info", {}).get("tags"),
    } for f in findings]

    result = {"status": status, "scanned": target, "tags": tags,
              "duration_s": duration, "returncode": rc,
              "count": len(slim), "findings": slim}
    if lifted:
        result["exclusions_lifted"] = lifted
    if timed_out:
        result["partial"] = True
        result["note"] = ("scan did NOT complete (hit the time limit). The findings "
                          "below are partial. Absence of a finding here is NOT evidence "
                          "of absence. Retry with a narrower tag set or report as untested.")
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # do not follow redirects: a redirect could leave the allowlisted host


def fetch_url(target, path="/", max_bytes=2000):
    """Read-only GET of one path on the approved host. Does not follow redirects."""
    _check_target(target)
    url = target.rstrip("/") + "/" + str(path).lstrip("/")
    # Re-check that the final URL host is still the approved one.
    _check_target(url)
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "agentic-offsec-poc"})
    try:
        with opener.open(req, timeout=10) as r:
            body = r.read(max_bytes).decode("utf-8", "replace")
            return {"status": "ok", "http_status": r.status, "url": url, "body_snippet": body}
    except urllib.error.HTTPError as e:
        # A 3xx (redirect, not followed) or 4xx/5xx means the endpoint EXISTS. Report the
        # status so the agent does not read "endpoint failed" for a live 500 or a redirect.
        return {"status": "ok", "http_status": e.code, "url": url,
                "note": f"endpoint responded with HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001 - connection-level failure
        return {"status": "error", "url": url, "error": str(e)}
