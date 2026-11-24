"""
Verify an audit log's tamper-evident hash chain.

Usage: python verify_audit.py audit/audit_<timestamp>.jsonl

Recomputes each record's SHA-256 from (previous hash + record body) and checks it
against the stored hash and the next record's prev_hash. Any edit, insertion, or
deletion breaks the chain and is reported.
"""
import sys
import json
import hashlib


def verify(path):
    prev = "0" * 64
    n = 0
    for i, line in enumerate(open(path), 1):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        stored = rec.pop("hash", None)
        if rec.get("prev_hash") != prev:
            return False, f"record {i}: prev_hash mismatch (chain broken)"
        body = json.dumps(rec, sort_keys=True)
        recomputed = hashlib.sha256((prev + body).encode()).hexdigest()
        if recomputed != stored:
            return False, f"record {i}: hash mismatch (record was altered)"
        prev = stored
        n += 1
    return True, f"OK: {n} records, chain intact"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python verify_audit.py <audit_log.jsonl>")
        sys.exit(2)
    ok, msg = verify(sys.argv[1])
    print(msg)
    sys.exit(0 if ok else 1)
