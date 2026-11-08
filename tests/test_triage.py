"""My own tests; they build tiny SARIF/Bandit files so they do not need fixtures/."""
import hashlib
import json
import random
import subprocess
import sys
from datetime import date

import pytest

from triage.core import (Finding, Suppression, apply_suppressions, dedupe, diff_baseline,
                         fingerprint, gate, issue_key, load_bandit, load_semgrep_sarif,
                         load_suppressions, normalize_path)

P = "diwan_invoicing"


def sarif(rules, results, tmp_path, name="s.sarif", extra_runs=()):
    run = {"tool": {"driver": {"rules": rules}}, "results": results}
    p = tmp_path / name
    p.write_text(json.dumps({"runs": [run, *extra_runs]}))
    return p


def res(rule="r1", level=None, line=3, uri="./invoicing/web.py", snippet="    x = 1\n    y"):
    r = {"ruleId": rule, "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                             "region": {"startLine": line, "snippet": {"text": snippet}}}}]}
    if level:
        r["level"] = level
    return r


def rule(rid="r1", score=None, level=None, tags=None):
    r = {"id": rid, "properties": {}}
    if score is not None:
        r["properties"]["security-severity"] = score
    if tags is not None:
        r["properties"]["tags"] = tags
    if level:
        r["defaultConfiguration"] = {"level": level}
    return r


def sev(tmp_path, rl, rs):
    return load_semgrep_sarif(sarif([rl], [rs], tmp_path), P)[0].severity


@pytest.mark.parametrize("score,exp", [("9.0", "critical"), ("7.0", "high"), ("4.0", "medium"),
                                       ("3.9", "low"), (9.5, "critical"), (7, "high")])
def test_sarif_score(tmp_path, score, exp):
    assert sev(tmp_path, rule(score=score, level="note"), res(level="note")) == exp


@pytest.mark.parametrize("score", ["0.0", "abc", 11, 0, True])
def test_sarif_bad_score_ignored(tmp_path, score):
    assert sev(tmp_path, rule(score=score), res(level="error")) == "high"


def test_sarif_levels(tmp_path):
    assert sev(tmp_path, rule(level="error"), res(level="note")) == "low"      # result overrides rule
    assert sev(tmp_path, rule(level="error"), res()) == "high"
    assert sev(tmp_path, rule(), res()) == "medium"                            # no default config
    assert sev(tmp_path, rule(), res(level="none")) == "info"


def test_sarif_cwe_runs_code(tmp_path):
    r2 = {"tool": {"driver": {"rules": [rule("r2")]}}, "results": [res("r2")]}
    fs = load_semgrep_sarif(sarif([rule(tags=["x", "CWE-89: SQLi", "CWE-1"])], [res()], tmp_path,
                                  extra_runs=[r2]), P)
    assert [f.cwe for f in fs] == [89, None] and len(fs) == 2
    assert fs[0].code == "    x = 1" and fs[0].path == "invoicing/web.py" and fs[0].line == 3


def bandit(tmp_path, results):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"results": results}))
    return load_bandit(p, P)


def brow(sev_="HIGH", conf="HIGH", line=10, code="9 a\n10     b = 2\n11 c\n", cwe=True):
    r = {"filename": "diwan_invoicing\\invoicing\\web.py", "line_number": line, "test_id": "B1",
         "issue_text": "t", "issue_severity": sev_, "issue_confidence": conf, "code": code}
    if cwe:
        r["issue_cwe"] = {"id": 89, "link": "x"}
    return r


@pytest.mark.parametrize("s,c,exp", [("HIGH", "HIGH", "high"), ("HIGH", "MEDIUM", "high"),
                                     ("HIGH", "LOW", "medium"), ("MEDIUM", "LOW", "low"),
                                     ("LOW", "LOW", "info"), ("LOW", "HIGH", "low"),
                                     ("WEIRD", "HIGH", "info"), ("WEIRD", "LOW", "info")])
def test_bandit_severity(tmp_path, s, c, exp):
    assert bandit(tmp_path, [brow(s, c)])[0].severity == exp


def test_bandit_code_line_and_cwe(tmp_path):
    f = bandit(tmp_path, [brow(cwe=False)])[0]
    assert f.cwe is None and f.code == "    b = 2" and f.path == "invoicing/web.py"
    assert bandit(tmp_path, [brow(line=9)])[0].code == "a"
    assert bandit(tmp_path, [brow(line=100, code="99 a\n100 z\n101 q")])[0].code == "z"
    assert bandit(tmp_path, [brow(line=10, code="99 a\n100 z\n101 q")])[0].code == ""
    assert bandit(tmp_path, [brow(line=3, code="2 a\n3 last")])[0].code == "last"


@pytest.mark.parametrize("raw", ["./invoicing/web.py", "diwan_invoicing\\invoicing\\web.py",
                                 "/home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py",
                                 "file:///home/r/diwan_invoicing/invoicing/web.py",
                                 "C:\\w\\diwan_invoicing\\invoicing\\web.py",
                                 "invoicing//./web.py", "invoicing/web.py"])
def test_paths(raw):
    assert normalize_path(raw, P) == "invoicing/web.py"


def F(**kw):
    d = dict(tool="semgrep", rule_id="r", path="a.py", line=1, severity="high", cwe=89, message="m", code="x = 1")
    d.update(kw)
    return Finding(**d)


def test_fingerprint():
    f = F()
    assert fingerprint(f) == hashlib.sha256(b"semgrep|r|a.py|x = 1").hexdigest()
    assert fingerprint(F(line=99, code="\t  x   =  1  ")) == fingerprint(f)
    for other in (F(tool="bandit"), F(rule_id="q"), F(path="b.py"), F(code="x = 2")):
        assert fingerprint(other) != fingerprint(f)


def test_issue_key_and_dedupe():
    assert issue_key(F(), {"semgrep:r": "SQLI"}) == "SQLI"
    assert issue_key(F(), {}) == "CWE-89" and issue_key(F(cwe=None), {}) == "semgrep:r"
    a, b = F(), F(tool="bandit", rule_id="B608", severity="medium")
    g = dedupe([b, a])
    assert len(g) == 1 and g[0].severity == "high" and g[0].tools == ["bandit", "semgrep"]
    c = F(tool="bandit", rule_id="B501", cwe=295)
    d = F(tool="bandit", rule_id="B113", cwe=400)
    assert len(dedupe([c, d])) == 2
    assert len(dedupe([F(cwe=None, rule_id="x"), F(tool="bandit", cwe=None, rule_id="y")],
                      {"semgrep:x": "K", "bandit:y": "K"})) == 1
    assert len(dedupe([F(), F(line=2)])) == 2


def test_order_and_property():
    rng = random.Random(1)
    fs = [F(path=rng.choice("abc") + ".py", line=rng.randint(1, 3), cwe=rng.choice([1, 2, None]),
            rule_id=rng.choice("xyz"), tool=rng.choice(["semgrep", "bandit"]),
            severity=rng.choice(["info", "low", "medium", "high", "critical"]), code=str(i))
          for i in range(60)]
    base = dedupe(fs)
    shuffled = fs[:]
    rng.shuffle(shuffled)
    again = dedupe(shuffled)
    assert [(g.key, g.path, g.line, g.severity, g.tools, g.fingerprints) for g in base] == \
           [(g.key, g.path, g.line, g.severity, g.tools, g.fingerprints) for g in again]
    assert sum(len(g.findings) for g in base) == len(fs)
    order = ["info", "low", "medium", "high", "critical"]
    for g in base:
        assert all(m.path == g.path and m.line == g.line for m in g.findings)
        assert g.severity == max((m.severity for m in g.findings), key=order.index)
    ranks = [(-order.index(g.severity), g.path, g.line, g.key) for g in base]
    assert ranks == sorted(ranks)


def entry(fp="a" * 64, reason="long enough reason", by="heba", exp="2026-11-10"):
    return {"fingerprint": fp, "reason": reason, "by": by, "expires": exp}


def test_suppression_validation():
    bad = [entry(fp="A" * 64), entry(fp="a" * 63), entry(reason="short"), entry(reason="   x   "),
           entry(by=" "), {k: v for k, v in entry().items() if k != "by"}, entry(exp="nope"),
           {k: v for k, v in entry().items() if k != "expires"}, "junk", entry(exp=None)]
    ok, invalid = load_suppressions([entry()] + bad)
    assert len(ok) == 1 and len(invalid) == len(bad)


def test_apply_suppressions_and_baseline():
    g1, g2 = dedupe([F()])[0], dedupe([F(path="z.py", code="q")])[0]
    fp = g1.fingerprints[0]
    mk = lambda exp: Suppression(fp, "r" * 10, exp, "me")
    today = date(2026, 11, 8)
    assert apply_suppressions([g1, g2], [mk(date(2026, 11, 8))], today) == ([g2], [g1])
    assert apply_suppressions([g1, g2], [mk(date(2026, 11, 7))], today) == ([g1, g2], [])
    # suppress via one member of a merged group
    merged = dedupe([F(), F(tool="bandit", rule_id="B")])[0]
    bfp = fingerprint(merged.findings[0])
    assert apply_suppressions([merged], [Suppression(bfp, "r" * 10, date(2027, 1, 1), "m")], today)[1] == [merged]
    new, ex, fixed = diff_baseline([g1, g2], {fp, "zz", "aa"})
    assert new == [g2] and ex == [g1] and fixed == ["aa", "zz"]
    moved = dedupe([F(line=500)])[0]  # same code, moved line => still existing
    assert diff_baseline([moved], {fp})[1] == [moved]


def test_gate():
    gs = [dedupe([F(severity=s, line=i)])[0] for i, s in enumerate(["low", "medium", "high"])]
    assert gate([], "low") is True
    assert [gate(gs, t) for t in ("info", "low", "medium", "high", "critical")] == [False, False, False, False, True]
    assert gate(gs[:2], "high") is True


def run(*args):
    return subprocess.run([sys.executable, "-m", "triage", *args], capture_output=True, text=True)


def test_cli(tmp_path):
    s = sarif([rule(score="8.0", tags=["CWE-89"])], [res()], tmp_path)
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"results": [brow(line=3, code="3     x = 1")]}))
    base = ["--sarif", str(s), "--bandit", str(b), "--project", P]
    r = run(*base)
    out = json.loads(r.stdout)
    assert r.returncode == 1 and out["passed"] is False and len(out["new"]) == 1
    assert set(out) == {"passed", "new", "existing", "suppressed", "fixed", "invalid_suppressions"}
    assert set(out["new"][0]) == {"key", "path", "line", "severity", "tools", "fingerprints"}
    fps = out["new"][0]["fingerprints"]
    (tmp_path / "base.json").write_text(json.dumps(fps))
    r = run(*base, "--baseline", str(tmp_path / "base.json"))
    assert r.returncode == 0 and len(json.loads(r.stdout)["existing"]) == 1
    sup = [entry(fp=fps[0], exp="2026-12-01"), {"bad": 1}]
    (tmp_path / "sup.json").write_text(json.dumps(sup))
    r = run(*base, "--suppressions", str(tmp_path / "sup.json"), "--today", "2026-11-08")
    o = json.loads(r.stdout)
    assert r.returncode == 0 and len(o["suppressed"]) == 1 and o["invalid_suppressions"] == 1
    assert run(*base, "--fail-on", "critical").returncode == 0
    assert run("--sarif", str(tmp_path / "nope"), "--bandit", str(b), "--project", P).returncode == 2
    (tmp_path / "bad.json").write_text("not json")
    assert run("--sarif", str(tmp_path / "bad.json"), "--bandit", str(b), "--project", P).returncode == 2
    assert run(*base, "--baseline", str(tmp_path / "bad.json")).returncode == 2
