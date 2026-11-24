"""
Audit trail: the "provable control" half of governed autonomy.

Every reasoning step, tool call, gate decision, tool result, and the final report
is appended to a per-run JSONL file. Two properties make it trustworthy:

  1. Append-only, per run: each run writes a NEW timestamped file. Earlier runs are
     never overwritten (the previous version truncated the log on every run).
  2. Tamper-evident: each record carries a SHA-256 hash of (previous hash + this
     record). Changing or deleting any record breaks the chain, which verify_audit.py
     detects. This is a PoC stand-in for append-only WORM storage in production.
"""
import json
import os
import hashlib
import datetime


class Audit:
    def __init__(self, path=None):
        if path is None:
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = f"audit/audit_{ts}.jsonl"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.prev_hash = "0" * 64  # genesis
        # Do NOT truncate an existing file; refuse to clobber one.
        if os.path.exists(path) and os.path.getsize(path) > 0:
            raise FileExistsError(f"audit file already exists: {path}")

    def log(self, event, **data):
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            **data,
            "prev_hash": self.prev_hash,
        }
        body = json.dumps(rec, sort_keys=True)
        rec_hash = hashlib.sha256((self.prev_hash + body).encode()).hexdigest()
        rec["hash"] = rec_hash
        self.prev_hash = rec_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec
