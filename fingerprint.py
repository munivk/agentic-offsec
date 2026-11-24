"""
Code fingerprint: one SHA-256 over the files that decide how a run behaves.

Every run records it in its audit log (run_start.meta.code_sha256), and run_clean.sh writes
it to evidence_clean/_meta.txt. To check that the code in front of you is the code that
produced the evidence, run this and compare:

    python fingerprint.py
"""
import glob
import hashlib
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FILES = ["policy.toml", "run_agent.py", "run_gate_live.py", "baseline.py", "demo_gate.py",
         "run_clean.sh"]


def code_files():
    agent = sorted(os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "agent", "*.py")))
    return agent + FILES


def code_sha256():
    h = hashlib.sha256()
    for rel in code_files():
        h.update(rel.encode() + b"\0")
        with open(os.path.join(ROOT, rel), "rb") as f:
            h.update(f.read())
        h.update(b"\0")
    return h.hexdigest()


if __name__ == "__main__":
    print(code_sha256())
