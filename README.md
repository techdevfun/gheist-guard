# gheist-guard

A local, deterministic, read-only behavioral detector for the Gheist
planted-workflow attack shape: one command, one verdict per repository,
one rotate checklist.

**Credit and independence.** "Gheist" is the name Wiz Research gave to
the campaign it reported in October 2026, and the detection pattern in
this tool comes from Wiz's published reporting and the community audit
runbooks that followed it. This tool is not affiliated with, endorsed
by, or connected to Wiz, and it does not claim to be the first to
detect any campaign.

## The problem

A token stolen from one developer machine (infostealer logs are the
documented main source) becomes an organization-wide secret dump with no
strange domain and no outbound connection for a firewall to catch. The
attacker pushes a branch named `ci-sync-` plus six characters, commits
a workflow that prints repository secrets base32-encoded into the run
log (GitHub masks secret values only when they appear verbatim), then
downloads the log through the GitHub API and deletes the run within
seconds. Wiz recovered more than 13,500 planted branches from more
than 850 compromised accounts.

GitHub's July 28, 2026 control holds suspicious runs in *public*
repositories for collaborator approval, but it does not cover private
repositories or GitHub Enterprise Server - exactly where this attack
succeeds. Deleting the branch or the run does not undo the exposure:
every secret the repository could read must be rotated.

Existing answers stop the wrong half of the problem (public repos only),
require the operator to already know the pattern and write the queries,
or scan for secret text instead of watching for the act. A dump
workflow contains no secret text, so no content scanner flags it.
gheist-guard watches the act, from the evidence that survives it: the
branch name, the audit-log sequence, and the tool fingerprint.

## Install

```sh
npm install -g gheist-guard   # once published to npm
```

From source:

```sh
npm ci
npm run build
node dist/cli.js scan <owner/repo>
```

Requires Node 20 or later. Zero runtime dependencies.

## Usage

```sh
# Scan one repository (REST path, read-only)
gheist-guard scan <owner/repo>

# Scan every repository in an organization (REST path)
gheist-guard scan --org <org>

# Audit-log path (organization-owner token required for live use;
# --events runs it against recorded audit-log payloads)
gheist-guard audit --org <org> --events audit-events.json

# Re-print the rotate checklist from a saved report, without re-scanning
gheist-guard scan <owner/repo> > report.json
gheist-guard checklist <owner/repo> --report report.json
```

The GitHub token may come from `--token` or `GITHUB_TOKEN`. A
fine-grained token with repository read scope is enough for the REST
path. Exit code: 0 on CLEAR, 1 on SUSPECT or CONFIRMED, 2 on usage or
API errors. One stderr summary line is always printed.

Allowlist legitimate automation (reported as SKIPPED with a reason,
never silently dropped):

```sh
gheist-guard scan <owner/repo> \
  --allow-branch-pattern '^ci-sync-.*$' \
  --allow-workflow .github/workflows/team-sync.yml
```

## Verdicts

- **CLEAR**: no rule fires.
- **SUSPECT**: a rule fires, but the full documented combination is not
  present. Carries the exact next check to run instead of a rotation
  demand. A partial signal is never silently CLEAR and never CONFIRMED.
- **CONFIRMED**: the branch pattern (R1) plus any of workflow identity
  (R2), dump content (R3), run lifecycle (R4), tool fingerprint (R5),
  or the self-hosted variant (R7). Always carries the ordered rotate
  checklist.

The name "Gheist" appears in a verdict only when the full documented
pattern matches. Anything less is SUSPECT with its evidence quoted.

```json
{
  "verdict": "CONFIRMED",
  "repo": "owner/repo",
  "path": "rest",
  "findings": [
    { "rule": "R1", "severity": "high",
      "evidence": "branch ci-sync-a1b2c3 matches ^ci-sync-[0-9a-z]{6}$" }
  ],
  "manifest": { "rulesVersion": "2026.10", "checkedAt": "2026-10-27" },
  "rotateChecklist": ["Revoke the token of <pusher>", "..."]
}
```

Full rule reference: [docs/RULES.md](docs/RULES.md).

## The rotate checklist

CONFIRMED verdicts print, in order: revoke the pushing token; rotate
every secret name the run could read; check OIDC roles assumable from
the matched ref; check the pushing machine for infostealer compromise.
The checklist lists secret **names** only. The tool never prints,
stores, or transmits a secret value, and its data model never carries
one. v1 never deletes, rotates, or revokes anything: the checklist
tells the operator what to do, in order; the operator does it.

## What this is NOT

- Not a static secret scanner (Gitleaks/TruffleHog job; explicitly out).
- Not a SIEM, monitoring service, malware database, or auto-remediation
  tool.
- Not a prevention control for public repositories: GitHub's approval
  hold already does that job, and this tool never approves held runs.

## Where rivals beat us (honest section)

- **GitHub's native controls beat us on authority and position.** The
  audit log is ground truth; the approval hold stops public execution
  before any dump. We only read what the platform records, and we
  cannot see a run deleted before our first scan unless the branch or
  the audit log still carries it.
- **Socket, StepSecurity, and GitGuardian beat us on
  threat-intelligence scale.** They see campaigns across the ecosystem;
  we see only your repositories. We will never be the first to name a
  new campaign, and we do not claim to be.
- **Gitleaks and TruffleHog beat us on secret-pattern breadth in code
  and history.** We do not scan secrets in code at all. Anyone who
  needs that should run one of them alongside this tool.
- **SIEM tooling beats us on central correlation across sources.** We
  are a single-purpose local tool.
- **Manual runbooks beat us on zero-install immediacy.** Copy-paste
  commands work today with no install. We earn the install with
  scheduling, reporting, false-positive discipline, and the checklist.

## Measured numbers (build 2026-10-27, fixtures only unless stated)

- Test suite: **52/52 green** (`npm test`), TypeScript strict, clean.
  Covers the REST adapter (stubbed fetch), the audit fetcher
  (phrases, paging, error, missing fields), audit evaluator edge
  cases, and REST/audit cross-path agreement and divergence.
- Fixture verdicts: CONFIRMED on every planted fixture (branch +
  workflow, sync-host variant, audit triple in 45s, `gheist`
  user-agent); CLEAR on every legitimate fixture; SUSPECT (never
  CONFIRMED, never silent CLEAR) on every partial-signal fixture.
- False-positive probe: 24 legitimate branch names + 5 legitimate
  workflows -> **0 CONFIRMED**, 1 SUSPECT (`ci-sync-config` matches
  the six-character pattern by design; documented boundary, see
  docs/RULES.md).
- Rule-evaluation latency (in-process, 500 iterations on the planted
  fixture): median **0.0045 ms**, p95 **0.0148 ms** per repository.
- Live REST end-to-end (real GitHub API, read-only, 2026-10-27): 3
  real repositories scanned, all CLEAR, exit 0 (vetgate, context-diet,
  breakcheck); plus a private scratch repository with a branch-only
  plant: SUSPECT pre-fix (R1 only) and CONFIRMED post-fix (R1+R2+R3)
  on verbatim live state. Evidence:
  [docs/live-scratch-evidence-2026-10-27.md](docs/live-scratch-evidence-2026-10-27.md).
  The scratch branch was deleted; the repository shell awaits
  owner-side deletion (API deletion is scope-blocked, 403).
- Demo (real CLI runs on fixtures, not staged): 9.4-second GIF
  [examples/demo.gif](examples/demo.gif) plus the full transcript
  [examples/demo-transcript.txt](examples/demo-transcript.txt).
  The GIF reveals the verbatim terminal output of a CONFIRMED run and
  a CLEAR run, nothing reworded.

## Limits, stated plainly

- **Audit-log path is fixture-tested only, end to end.** No
  organization-owner account is available to run a live audit-log
  end-to-end test. The live fetcher queries all four lifecycle
  phrases (created, completed, deleted, prepared), paged to 1000
  events, and maps prepared secret names defensively; the
  prepared-event secret field name is not yet confirmed against a
  real organization response. The report always states which path
  ran. The REST path is the live-measured end-to-end path, and it
  reads workflows from the default branch and from every R1-matching
  branch, so a branch-only plant is visible live.
- **GitHub Enterprise Server** site-admin logs are documented but
  untested (no instance available).
- **Pull-request association is an approximation**: a workflow commit
  with an associated pull request is treated as reviewed; a commit with
  none is treated as unreviewed.
- **No claim of detecting live campaigns.** All detection claims rest
  on fixtures until a real user reports a real hit.
- **A run deleted before the first scan is invisible to the REST path.**
  That is why the audit-log path exists, and why the report states
  which path ran.

## GitHub Action

```yaml
- uses: techdevfun/gheist-guard@v1
  with:
    target: my-org/my-repo   # defaults to the current repository
```

Runs on a schedule and on `workflow_dispatch`, fails the job on
SUSPECT or CONFIRMED, and uploads the report as an artifact. The
Action never approves held runs, never deletes branches or runs, and
never touches credentials.

## License

MIT.
