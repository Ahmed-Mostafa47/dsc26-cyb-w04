"""python -m triage --sarif S --bandit B --project NAME [...]  (exit 0 pass, 1 fail, 2 bad input)"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from .core import (SEVERITIES, apply_suppressions, dedupe, diff_baseline, gate,
                   load_bandit, load_semgrep_sarif, load_suppressions)


def _group(g) -> dict:
    return {"key": g.key, "path": g.path, "line": g.line, "severity": g.severity,
            "tools": g.tools, "fingerprints": g.fingerprints}


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today", type=date.fromisoformat, default=None)
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES)
    args = ap.parse_args(argv)  # argparse itself exits with 2 on bad usage
    today = args.today or date.today()

    try:
        findings = (load_semgrep_sarif(args.sarif, args.project)
                    + load_bandit(args.bandit, args.project))
        equivalences = _load_json(args.equivalences) if args.equivalences else {}
        baseline = _load_json(args.baseline) if args.baseline else []
        entries = _load_json(args.suppressions) if args.suppressions else []
        if not isinstance(equivalences, dict) or not isinstance(baseline, list) \
                or not isinstance(entries, list):
            raise ValueError("wrong JSON shape")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"triage: cannot read input: {exc}", file=sys.stderr)
        return 2

    groups = dedupe(findings, equivalences)
    suppressions, invalid = load_suppressions(entries)
    active, suppressed = apply_suppressions(groups, suppressions, today)
    new, existing, fixed = diff_baseline(active, {b for b in baseline if isinstance(b, str)})
    passed = gate(new, args.fail_on)

    print(json.dumps({
        "passed": passed,
        "new": [_group(g) for g in new],
        "existing": [_group(g) for g in existing],
        "suppressed": [_group(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }, indent=2, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
