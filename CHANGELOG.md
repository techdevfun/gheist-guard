# Changelog

## 0.1.1 - 2026-10-27 (local gap-fill; not yet published)

- REST adapter now reads workflows from the default branch AND from
  every R1-matching branch (contents API with `?ref=<branch>`), so a
  branch-only plant combines R1 with R2/R3 into CONFIRMED on the live
  path. Previously a branch-only plant scored SUSPECT only.
- Audit-log fetcher now queries all four lifecycle phrases (created,
  completed, deleted, prepared) instead of two, pages to 1000 events,
  and maps prepared secret names defensively. Previously the R4
  triple could never form from live data for lack of the created
  phrase.
- Tests: 35 to 52, all green. New: REST adapter tests (stubbed fetch),
  audit fetcher tests (phrases, paging, error, missing fields),
  audit evaluator edge cases (out-of-order, duplicates, negative
  delta, invalid timestamp, branch fallback, interleaved runs,
  prepared dedup, empty input), REST/audit cross-path tests.
- Docs: `docs/RULES.md` gains an exact per-path visibility section
  (what each path sees and cannot see, including the documented
  REST-SUSPECT vs audit-CONFIRMED divergence); README limits updated
  to match the code.
- Demo: 9.4-second GIF from a real pty run (CONFIRMED + CLEAR) plus
  a fresh verbatim transcript in `examples/`.
- Live verification on a private scratch repository (deleted branch;
  repository shell awaits owner-side deletion, see
  `docs/live-scratch-evidence-2026-10-27.md`): branch-only plant
  scored SUSPECT pre-fix and CONFIRMED post-fix on verbatim live
  REST state. No real secret was used; only the invented name
  `FAKE_EXAMPLE`.

## 0.1.0 - 2026-10-27 (local build; not yet published)

- Initial release candidate: TypeScript CLI (zero runtime dependencies)
  plus a composite GitHub Action mirror.
- Commands: `scan` (REST path, plus `--org` aggregation),
  `audit` (audit-log path, `--events` fixture mode),
  `checklist` (re-print from a saved report).
- Rules R1-R7 (branch pattern, workflow identity, dump content,
  run lifecycle, tool fingerprint, generic unreviewed workflow,
  self-hosted variant); verdicts CLEAR / SUSPECT / CONFIRMED.
- Read-only by default: never deletes, rotates, or revokes anything;
  rotate checklist lists secret NAMES only, never values.
