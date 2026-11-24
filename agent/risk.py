"""
The impact gate: per-action risk scoring, the governance thesis made real.

Every action the agent proposes is scored BEFORE it runs. Low-risk actions run on their
own, medium-risk actions run and are flagged for review, and high-risk actions stop for a
human to approve. What each level does, and which tags and paths are risky, come from the
buyer's policy file (policy.toml), not from this code.

This is deliberately simple (a rule table) because a proof of concept only needs to show
the gate deciding and a human checkpoint firing. One dimension (tag and path sensitivity)
is computed for real; reversibility, blast radius and scope are coarse labels.
"""
import hashlib
import tomllib
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.toml"
VALID_ACTIONS = {"run", "run_and_flag", "ask_human", "deny"}
HIGH_FLOOR = {"ask_human", "deny"}  # high risk may never run without a human


class PolicyError(ValueError):
    pass


def load_policy(path=POLICY_PATH):
    """Load and validate the policy. Any problem stops the program: a control that a typo
    can loosen is not a control. The policy can tighten the gate, never go below the floor."""
    raw = Path(path).read_bytes()
    policy = tomllib.loads(raw.decode())
    levels = policy.get("levels", {})
    for level in ("low", "medium", "high"):
        if levels.get(level) not in VALID_ACTIONS:
            raise PolicyError(f"policy: levels.{level} = {levels.get(level)!r}; "
                              f"must be one of {sorted(VALID_ACTIONS)}")
    if levels["high"] not in HIGH_FLOOR:
        raise PolicyError(f"policy: levels.high = {levels['high']!r} is below the floor; "
                          f"high risk must be one of {sorted(HIGH_FLOOR)}")
    passive, active = set(policy["tags"]["passive"]), set(policy["tags"]["active"])
    if not active:
        raise PolicyError("policy: tags.active is empty")
    if passive & active:
        raise PolicyError(f"policy: tags in both passive and active: {sorted(passive & active)}")
    if not policy.get("allowed_hosts"):
        raise PolicyError("policy: allowed_hosts is empty")
    return policy, hashlib.sha256(raw).hexdigest()


POLICY, POLICY_SHA256 = load_policy()  # the hash goes into every run's audit log
PASSIVE_TAGS = set(POLICY["tags"]["passive"])
ACTIVE_TAGS = set(POLICY["tags"]["active"])
SENSITIVE_PATH_HINTS = tuple(POLICY["paths"]["sensitive"])
LEVEL_ACTIONS = POLICY["levels"]  # low/medium/high -> run / run_and_flag / ask_human / deny


def score_action(tool_name, params):
    """
    Return {level: low|medium|high, reason, dimensions}. A production version would be
    a policy engine (e.g. OPA) with asset criticality from the CMDB.
    """
    if tool_name == "fetch_url":
        path = str(params.get("path") or "/").lower()
        sensitive = next((h for h in SENSITIVE_PATH_HINTS if h in path), None)
        if sensitive:
            return {"level": "medium",
                    "reason": f"read-only GET of a sensitive path ({sensitive})",
                    "dimensions": {"reversibility": "reversible", "blast_radius": "single page",
                                   "data_sensitivity": "may expose confidential data",
                                   "in_scope": True}}
        return {"level": "low", "reason": "single read-only GET of a non-sensitive path",
                "dimensions": {"reversibility": "reversible", "blast_radius": "single page",
                               "data_sensitivity": "low", "in_scope": True}}

    if tool_name == "run_nuclei":
        tags = [t.lower() for t in (params.get("tags") or [])]
        if not tags:
            return {"level": "high",
                    "reason": "unbounded scan: no tags, would run the whole template library",
                    "dimensions": {"reversibility": "unknown", "blast_radius": "target service",
                                   "data_sensitivity": "unknown", "in_scope": True}}
        active = sorted(set(tags) & ACTIVE_TAGS)
        if active:
            return {"level": "high",
                    "reason": f"active tags send payloads or attempt logins: {active}",
                    "dimensions": {"reversibility": "may change target state",
                                   "blast_radius": "target service",
                                   "data_sensitivity": "may touch auth/data", "in_scope": True}}
        unknown = sorted(set(tags) - PASSIVE_TAGS - ACTIVE_TAGS)
        if unknown:
            return {"level": "high",
                    "reason": f"unknown tags, intent not established: {unknown}",
                    "dimensions": {"reversibility": "unknown", "blast_radius": "unknown",
                                   "data_sensitivity": "unknown", "in_scope": True}}
        return {"level": "low", "reason": "detection-only scan (passive tags)",
                "dimensions": {"reversibility": "reversible", "blast_radius": "target service",
                               "data_sensitivity": "none", "in_scope": True}}

    return {"level": "high", "reason": f"unknown tool {tool_name}",
            "dimensions": {"in_scope": False}}
