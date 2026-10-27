# Rules reference (rules version 2026.10)

gheist-guard is deterministic: the same repository state plus the same
rules version gives the same verdict, byte for byte, excluding the
`checkedAt` timestamp. No model, no score, no heuristics that cannot be
stated. Every finding quotes the exact matched string and its location.

## Verdict levels

- **CLEAR**: no rule fires.
- **SUSPECT**: a rule fires, but the full documented combination is not
  present. A SUSPECT verdict carries the exact next check to run instead
  of a rotation demand. A partial signal is never silently CLEAR and
  never CONFIRMED.
- **CONFIRMED**: R1 fires plus any of R2, R3, R4, R5, R7. A CONFIRMED
  verdict always carries the ordered rotate checklist.

The name "Gheist" appears in a verdict only when the full documented
pattern matches. Anything less is SUSPECT with its evidence quoted.

## Rules

### R1 - branch-pattern (high)
Branch name matches `^ci-sync-[0-9a-z]{6}$` exactly. Alone: SUSPECT.
Calibration notes (measured on fixtures):
- `ci-sync-config` matches: "config" is six lowercase letters. A team
  that legitimately names a branch `ci-sync-config` gets SUSPECT with
  the audit-log next check, not CONFIRMED. This is the documented
  boundary, not a bug: the pattern alone never confirms.
- `ci-sync-a1b2c3d` (7 chars), `CI-SYNC-A1B2C3` (uppercase),
  `ci-sync-a1b2` (4 chars), `ci-sync-a1b2c3-foo` (suffix) do not match.

### R2 - workflow-identity (high)
File `.github/workflows/sync-check.yml` added with commit message
`ci: sync config`, unsigned push, no pull request or review.
Combined with R1: CONFIRMED. On the live REST path the workflow is
read from the default branch and from every branch matching R1
(contents API with `?ref=<branch>`); a workflow found on a matched
branch is attributed to that branch, so a branch-only plant still
combines with R1. A workflow on any other branch is not read.

### R3 - dump-content (high)
Workflow content prints environment or secrets through base32 or base64
encoding to stdout, or dumps the full environment (`printenv`).
Combined with R1: CONFIRMED. Encoding a non-secret value, or using a
secret normally without encoding, does not fire R3.

### R4 - run-lifecycle, audit-log path only (high)
A workflow run on a matched branch completes and is deleted within 60
seconds (created, completed, deleted event triple). Combined with R1:
CONFIRMED. The 60-second window is calibrated on fixtures: a 45-second
triple fires, a 300-second triple does not, the 60-second boundary is
inclusive, 61 seconds does not fire. A triple on a non-matching branch
does not fire R4 by definition.

### R5 - tool-fingerprint, audit-log path only (high)
An audit-log event with user agent `gheist`. One finding per run, not
per event. Combined with R1: CONFIRMED.

### R6 - generic unreviewed-workflow (medium)
A workflow file added or changed without a pull request or review AND
any exfiltration indicator: a hardcoded IP URL, a `curl|sh` /
`wget|sh` chain, or `fetch-depth: 0` plus a history/credential grep.
Alone: SUSPECT. This rule catches the adjacent GhostAction shape
(a fake security-audit workflow on the default branch exfiltrating to a
hardcoded IP) without claiming it is Gheist.

### R7 - self-hosted variant (high)
A job named `sync-host` plus a host-enumeration indicator (Docker
socket access, `/proc/` reading, process-environment reading, mounted
container search, credential-format hunt). Combined with R1: CONFIRMED.

## Allowlist

`--allow-branch-pattern <regex>` and `--allow-workflow <path>` move
matching findings to the report's `skipped` list with their reason.
Allowlisted items are never silently dropped. Legitimate automation with
distinct prefixes (renovate, dependabot) does not match R1 and needs no
allowlist entry.

## Paths and what each path sees (and cannot see)

- **REST path** (`scan`): branch names (all branches); workflow files
  on the default branch and on every branch matching R1 (read with
  `?ref=<branch>`); workflow content; commit message, signature
  verification, and pull-request association for each workflow file.
  It cannot see: a run that was deleted before the first scan;
  audit-log-only fields (prepared secret names, tool user agent);
  workflow content on branches other than the default and the R1
  matches. Private repositories need a token; public repositories
  scan unauthenticated. This is the live-measured end-to-end path.
- **Audit-log path** (`audit`): created/completed/deleted
  workflow-run events, prepared-workflow-job events (secret NAMES for
  the checklist), actors, and the tool user agent, paired into
  lifecycles. It cannot see workflow content, so it never fires R2,
  R3, R6, or R7. It requires an organization-owner token; the live
  fetcher queries all four lifecycle phrases, paged to 1000 events.
  The prepared-event secret field name is not yet confirmed against a
  real organization response (no org-owner account is available), so
  prepared inventory stays fixture-verified and a row without an
  array `secrets` field simply contributes no names. End-to-end, the
  audit path is tested against recorded fixture payloads only. The
  report always states which path ran.
- **Agreement and documented divergence.** The same planted scenario
  confirms on both paths with the same matched branch. Divergence is
  expected, not a contradiction: a branch-only REST result is SUSPECT
  with an audit-log next check, while an audit triple on the same
  branch is CONFIRMED, because a run deleted before the first REST
  scan leaves no REST evidence. The SUSPECT report never demands
  rotation on a partial signal.
- **GitHub Enterprise Server** site-admin logs are documented but
  untested (no instance available). This is a stated limit, not a claim.
- **Pull-request association** is an approximation: a workflow commit
  with an associated pull request is treated as reviewed; a commit with
  none is treated as unreviewed.

## Rotate checklist

CONFIRMED verdicts print, in order: revoke the pushing token; rotate
every secret name the run could read; check OIDC roles assumable from
the matched ref; check the pushing machine for infostealer compromise.
The checklist lists secret NAMES only. The tool never prints, stores, or
transmits a secret value, and its data model never carries one.
