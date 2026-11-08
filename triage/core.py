"""SAST triage: load, normalise, fingerprint, merge, suppress, baseline, gate."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]  # lowest to highest
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_ONE_LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
_CWE_RE = re.compile(r"CWE-([0-9]+)", re.ASCII)
_FP_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted({fingerprint(f) for f in self.findings})


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


# --------------------------------------------------------------------------- paths

def normalize_path(raw: str, project: str) -> str:
    p = str(raw).replace("\\", "/")
    if p[:7].lower() == "file://":
        p = p[7:]
    segs = [s for s in p.split("/") if s not in ("", ".")]
    if project and project in segs:
        last = len(segs) - 1 - segs[::-1].index(project)
        segs = segs[last + 1:]
    return "/".join(segs)


# ------------------------------------------------------------------------ fingerprint

def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    return hashlib.sha256(f"{f.tool}|{f.rule_id}|{f.path}|{code}".encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- loaders

def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _as_dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _score(value) -> float | None:
    """security-severity as a number in (0, 10], else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        try:
            num = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(num) or not 0 < num <= 10:
        return None
    return num


def _sarif_severity(result: dict, rule: dict) -> str:
    score = _score(_as_dict(rule.get("properties")).get("security-severity"))
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    level = result.get("level")
    if level is None:
        level = _as_dict(rule.get("defaultConfiguration")).get("level")
    if level is None:
        level = "warning"
    return _SARIF_LEVELS.get(level, "medium") if isinstance(level, str) else "medium"


def _sarif_cwe(rule: dict) -> int | None:
    tags = _as_dict(rule.get("properties")).get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str):
                m = _CWE_RE.match(tag)
                if m:
                    return int(m.group(1))
    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for run in _as_dict(data).get("runs") or []:
        run = _as_dict(run)
        driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
        rule_list = [_as_dict(r) for r in driver.get("rules") or []]
        for ext in _as_dict(run.get("tool")).get("extensions") or []:
            rule_list += [_as_dict(r) for r in _as_dict(ext).get("rules") or []]
        rules = {r.get("id"): r for r in rule_list}
        for res in run.get("results") or []:
            res = _as_dict(res)
            rule_id = res.get("ruleId")
            rule = rules.get(rule_id)
            if rule is None:  # fall back to ruleIndex when the id is not listed
                idx = res.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(driver.get("rules") or []):
                    rule = _as_dict(driver["rules"][idx])
                    rule_id = rule_id or rule.get("id")
            rule = rule or {}
            locs = res.get("locations") or [{}]
            phys = _as_dict(_as_dict(locs[0]).get("physicalLocation"))
            uri = _as_dict(phys.get("artifactLocation")).get("uri", "")
            region = _as_dict(phys.get("region"))
            lines = str(_as_dict(region.get("snippet")).get("text") or "").splitlines()
            line = region.get("startLine")
            findings.append(Finding(
                tool="semgrep",
                rule_id=str(rule_id),
                path=normalize_path(uri, project),
                line=line if isinstance(line, int) else 0,
                severity=_sarif_severity(res, rule),
                cwe=_sarif_cwe(rule),
                message=str(_as_dict(res.get("message")).get("text") or ""),
                code=lines[0] if lines else "",
            ))
    return findings


def _bandit_code(block, line_number) -> str:
    if not isinstance(block, str):
        return ""
    for raw in block.splitlines():
        num, _, text = raw.partition(" ")
        if num == str(line_number):
            return text
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for res in _as_dict(data).get("results") or []:
        res = _as_dict(res)
        sev = _BANDIT_SEV.get(str(res.get("issue_severity", "")).upper(), "info")
        if str(res.get("issue_confidence", "")).upper() == "LOW":
            sev = _ONE_LOWER[sev]
        cwe_id = _as_dict(res.get("issue_cwe")).get("id")
        if isinstance(cwe_id, str) and cwe_id.isascii() and cwe_id.isdigit():
            cwe_id = int(cwe_id)
        cwe = cwe_id if isinstance(cwe_id, int) and not isinstance(cwe_id, bool) else None
        line = res.get("line_number")
        line = line if isinstance(line, int) else 0
        findings.append(Finding(
            tool="bandit",
            rule_id=str(res.get("test_id", "")),
            path=normalize_path(res.get("filename", ""), project),
            line=line,
            severity=sev,
            cwe=cwe,
            message=str(res.get("issue_text") or ""),
            code=_bandit_code(res.get("code"), line),
        ))
    return findings


# ------------------------------------------------------------------------------ merge

def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    eq = (equivalences or {}).get(f"{f.tool}:{f.rule_id}")
    if eq:
        return eq
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return f"{f.tool}:{f.rule_id}"


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    eq = equivalences or {}
    buckets: dict[tuple[str, int, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, eq)), []).append(f)
    groups = []
    for (path, line, key), members in buckets.items():
        members = sorted(members, key=lambda m: (m.tool, m.rule_id, m.severity, m.message, m.code))
        top = max((m.severity for m in members), key=lambda s: _RANK.get(s, -1))
        groups.append(Group(key=key, path=path, line=line, severity=top, findings=members))
    groups.sort(key=lambda g: (-_RANK.get(g.severity, -1), g.path, g.line, g.key))
    return groups


# ------------------------------------------------------------------------ suppressions

def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid: list[Suppression] = []
    invalid: list[dict] = []
    for entry in entries:
        try:
            if not isinstance(entry, dict):
                raise ValueError("not an object")
            fp, reason, by, exp = (entry.get(k) for k in ("fingerprint", "reason", "by", "expires"))
            if not (isinstance(fp, str) and _FP_RE.fullmatch(fp)):
                raise ValueError("fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("by")
            if not isinstance(exp, str):
                raise ValueError("expires")
            valid.append(Suppression(fp, reason, date.fromisoformat(exp), by))
        except (ValueError, TypeError):
            invalid.append(entry)
    return valid, invalid


def apply_suppressions(groups, suppressions, today: date):
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active, suppressed = [], []
    for g in groups:
        (suppressed if live.intersection(g.fingerprints) else active).append(g)
    return active, suppressed


# --------------------------------------------------------------------------- baseline

def diff_baseline(groups, baseline: set[str]):
    baseline = set(baseline)
    new, existing, seen = [], [], set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        (existing if baseline.intersection(fps) else new).append(g)
    return new, existing, sorted(baseline - seen)


# ------------------------------------------------------------------------------- gate

def gate(new_active: list[Group], fail_on: str) -> bool:
    if fail_on not in _RANK:
        raise ValueError(f"fail_on must be one of {SEVERITIES}")
    threshold = _RANK[fail_on]
    return not any(_RANK.get(g.severity, -1) >= threshold for g in new_active)
