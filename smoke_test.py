"""Run every command from WALKTHROUGH.md and report which ones work.

Run this before a demo. It executes the real commands against the real demo
targets, checks each one produced what the walkthrough claims, and writes all
output to ``demo-output/`` so you can read it afterwards.

    python smoke_test.py

Exit code is 0 only when every check passes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
GOAT = REPO.parent / "github-actions-goat"
DEMO = REPO.parent / "demo-repo"
OUT = REPO / "demo-output"

PY = [sys.executable, "-m", "cicd_detector"]

# Colour only when stdout is a real terminal. Piped or redirected output would
# otherwise carry escape sequences into whatever reads it.
if sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
    GREEN, RED, YELLOW, DIM, RESET = (
        "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
    )
else:
    GREEN = RED = YELLOW = DIM = RESET = ""

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))
    return ok


def run(argv: list[str], save_as: str | None = None, timeout: int = 600):
    """Run a command, capture output, optionally save it."""

    started = time.monotonic()
    proc = subprocess.run(
        argv, cwd=REPO, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace",
    )
    elapsed = time.monotonic() - started
    body = (proc.stdout or "") + (proc.stderr or "")
    if save_as:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / save_as).write_text(body, encoding="utf-8")
    return proc.returncode, body, elapsed


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


# -- preflight -----------------------------------------------------------------

def preflight() -> bool:
    section("Preflight")
    code, body, _ = run(PY + ["--version"])
    ok = check("cicd_detector importable", code == 0, body.strip()[:60])
    if not ok:
        print(f"\n{RED}Stop.{RESET} Run:  pip install -e \".[dev]\"  from {REPO}")
        return False

    check("goat target present", GOAT.is_dir(), str(GOAT))
    demo_is_git = (DEMO / ".git").is_dir()
    check("demo-repo present and is a git repo", demo_is_git, str(DEMO))
    if not demo_is_git and DEMO.exists():
        print(
            f"    {YELLOW}demo-repo exists but has no .git — rebuild it:{RESET}\n"
            f"    python examples/build_cicd_demo.py ../demo-repo --force"
        )
    return GOAT.is_dir() and demo_is_git


# -- the walkthrough steps -----------------------------------------------------

def step_goat() -> None:
    section("Step 1 — scan github-actions-goat")
    code, body, secs = run(
        PY + ["scan", str(GOAT), "--no-llm", "--top", "3"], "01-goat-scan.txt"
    )
    check("scan exits 0", code == 0, f"{secs:.1f}s")
    check("24 of 24 workflows parsed", "24 of 24" in body)
    check("no rule errors", "RULE ERRORS" not in body)
    check("has CRITICAL findings", "CRITICAL=" in body)
    check("built an attack graph", "ATTACK GRAPH" in body)

    # The tj-actions detection is the headline claim; verify precisely.
    code, body, _ = run(
        PY + ["analyze", str(GOAT), "--rule", "SCRIPT_INJECTION", "--format", "json"],
        "02-goat-injection.json",
    )
    ok = code == 0
    tj = []
    if ok:
        try:
            data = json.loads(body[body.index("{"):])
            tj = [
                f for f in data["findings"]
                if "tj-actions-changed-files-incident" in f["file"]
            ]
        except (ValueError, KeyError):
            ok = False
    check("tj-actions injection found", bool(tj))
    if tj:
        check(
            "…at the right line (33)",
            tj[0]["line"] == 33,
            f"reported line {tj[0]['line']}",
        )


def step_grading() -> None:
    section("Step 1b — grading, not shouting")
    code, body, _ = run(
        PY + ["analyze", str(GOAT), "--rule", "DANGEROUS_TRIGGER", "--format", "json"],
        "03-goat-triggers.json",
    )
    by_job: dict[str, str] = {}
    if code == 0:
        try:
            data = json.loads(body[body.index("{"):])
            for f in data["findings"]:
                by_job[f"{Path(f['file']).name}:{f['job']}"] = f["severity"]
        except (ValueError, KeyError):
            pass

    vulnerable = by_job.get("toc-tou.yml:vulnerable-pattern")
    prtarget = by_job.get("PRTargetWorkflow.yml:pr-target-check")
    check("toc-tou vulnerable-pattern is CRITICAL", vulnerable == "CRITICAL", str(vulnerable))
    check(
        "PRTargetWorkflow graded lower (bare checkout)",
        prtarget in {"LOW", "INFO", "MEDIUM"},
        str(prtarget),
    )


def step_taint() -> None:
    section("Step 1c — taint precision (the decoy test)")
    code, body, _ = run(
        PY + ["analyze", str(GOAT), "--rule", "SECRET_EXPOSURE", "--format", "json"],
        "04-goat-secrets.json",
    )
    leaks = []
    if code == 0:
        try:
            data = json.loads(body[body.index("{"):])
            leaks = [
                f for f in data["findings"]
                if "secret-in-build-log" in f["file"]
                and f["metadata"].get("sink") == "PRINT_VALUE"
            ]
        except (ValueError, KeyError):
            pass
    check("the real leak is reported", bool(leaks))
    if leaks:
        check("…on line 29", leaks[0]["line"] == 29, f"line {leaks[0]['line']}")
        check(
            "…marked derived (defeats log masking)",
            leaks[0]["metadata"].get("derived") is True,
        )
        check(
            "the decoy echo is NOT reported",
            len(leaks) == 1,
            f"{len(leaks)} print-sink finding(s)",
        )


def step_demo() -> None:
    section("Step 2 — the staged-attack demo repo")
    code, body, secs = run(PY + ["scan", str(DEMO), "--no-llm"], "05-demo-scan.txt")
    check("scan exits 0", code == 0, f"{secs:.1f}s")
    check("git history was read", "commits," in body and "not analysed" not in body)
    check("found the exfiltration", "PYPI_API_TOKEN is sent to a remote host" in body)
    check("found the unpinned action", "build-helpers/version-utils@v2" in body)
    check("found attack paths", "ATTACK PATHS" in body and "ATTACK PATHS (0)" not in body)

    code, body, _ = run(
        PY + ["analyze", str(DEMO), "--rule", "WORKFLOW_HISTORY_CHANGE"],
        "06-demo-history.txt",
    )
    check("history correlation produced findings", code == 0 and "R. Vance" in body)
    check("shows the permission widening (C2)", "contents: write" in body)
    check("shows the network call (C3)", "build-telemetry.example.net" in body)


def step_graph() -> None:
    section("Step 3 — the DAG")
    outdir = OUT / "graph"
    code, body, _ = run(
        PY + ["graph", str(DEMO), "--output-dir", str(outdir)], "07-demo-graph.txt"
    )
    check("graph exits 0", code == 0)
    for name in ("attack_graph.json", "attack_graph.svg", "attack_graph.dot",
                 "attack_graph.graphml"):
        f = outdir / name
        check(f"wrote {name}", f.is_file(), f"{f.stat().st_size:,} bytes" if f.is_file() else "")

    svg = outdir / "attack_graph.svg"
    if svg.is_file():
        text = svg.read_text(encoding="utf-8")
        check("svg is well-formed", text.startswith("<svg") and text.rstrip().endswith("</svg>"))
        check("svg is not empty of nodes", text.count("<rect") > 1)

    jsonf = outdir / "attack_graph.json"
    if jsonf.is_file():
        data = json.loads(jsonf.read_text(encoding="utf-8"))
        check("graph refused no edges silently", data["summary"]["rejected_edges"] == 0)
        unevidenced = [
            e for e in data["edges"]
            if e["type"] in ("sends_to", "interpolated_into", "supplies")
            and not e["evidence_ids"]
        ]
        check("every security edge carries evidence", not unevidenced)


def step_rules() -> None:
    section("Step 4 — rules")
    code, body, _ = run(PY + ["rules"], "08-rules.txt")
    expected = [
        "ACTION_UNPINNED", "EXCESSIVE_PERMISSIONS", "DANGEROUS_TRIGGER",
        "SCRIPT_INJECTION", "SECRET_EXPOSURE", "REMOTE_CODE_FETCH",
        "UNTRUSTED_CODE_EXECUTION", "ARTIFACT_TAMPERING", "RELEASE_RISK",
        "THIRD_PARTY_ACTION", "WORKFLOW_HISTORY_CHANGE",
    ]
    check("lists all 11 rules", all(r in body for r in expected))
    code, body, _ = run(PY + ["rules", "--explain", "SECRET_EXPOSURE"], "09-rule-explain.txt")
    check("--explain works", code == 0 and "masking" in body)


def step_dogfood() -> None:
    section("Step 5 — dogfooding: scan ourselves")
    code, body, _ = run(
        PY + ["scan", str(REPO), "--no-llm", "--no-history"], "10-self-scan.txt"
    )
    check("self-scan exits 0", code == 0)
    check("reads our own ci.yml", "ci.yml" in body or "No findings" in body)


def step_llm() -> None:
    section("Step 6 — LLM correlation")
    has_key = bool(
        os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    )
    if not has_key:
        code, body, _ = run(PY + ["scan", str(DEMO), "--top", "0"], "11-llm-skipped.txt")
        check("no key: step is skipped, not faked", "skipped:" in body)
        print(f"    {YELLOW}Set GEMINI_API_KEY to test the live path.{RESET}")
        return

    code, body, secs = run(PY + ["scan", str(DEMO), "--top", "0"], "11-llm-live.txt", timeout=300)
    check("scan exits 0 with LLM enabled", code == 0, f"{secs:.1f}s")
    ok = "verdict     :" in body
    check("model returned a usable analysis", ok)
    if not ok:
        for line in body.splitlines():
            if "Gemini request failed" in line:
                print(f"    {YELLOW}{line.strip()[:160]}{RESET}")
    else:
        check("citations are grounded", "grounded in :" in body)
        check("no invented finding ids", "were not in its context" not in body)


def step_tests() -> None:
    section("Step 7 — tests")
    code, body, secs = run(
        [sys.executable, "-m", "pytest", "-q", "-k", "cicd"], "12-tests.txt", timeout=900
    )
    passed = "passed" in body and " failed" not in body.split("passed")[0]
    check("cicd test suite green", code == 0 and passed, f"{secs:.1f}s")
    for line in body.splitlines():
        if "passed" in line:
            print(f"    {DIM}{line.strip()}{RESET}")
            break


def main() -> int:
    print("=" * 68)
    print("WALKTHROUGH SMOKE TEST")
    print("=" * 68)
    print(f"repo   : {REPO}")
    print(f"goat   : {GOAT}")
    print(f"demo   : {DEMO}")
    print(f"output : {OUT}")

    if not preflight():
        return 1

    step_goat()
    step_grading()
    step_taint()
    step_demo()
    step_graph()
    step_rules()
    step_dogfood()
    step_llm()
    step_tests()

    failed = [name for name, ok, _ in results if not ok]
    print("\n" + "=" * 68)
    if failed:
        print(f"{RED}{len(failed)} of {len(results)} checks FAILED{RESET}")
        for name in failed:
            print(f"  - {name}")
    else:
        print(f"{GREEN}All {len(results)} checks passed.{RESET}")
    print(f"\nOutput saved in: {OUT}")
    print(f"Open the diagram: {OUT / 'graph' / 'attack_graph.svg'}")
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
