import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRest, evaluateAudit } from "../dist/rules.js";
import { computeVerdict, suspectNextCheck } from "../dist/verdict.js";

// The two paths look at the same attack through different evidence.
// These tests pin where they agree, where they legitimately diverge,
// and that the divergence is documented behavior, not a contradiction:
// a run deleted before the first REST scan is invisible to REST, and
// REST's SUSPECT report says exactly that by pointing at the audit log.

const PLANTED_CONTENT = [
  "name: sync-check",
  "on: [push]",
  "jobs:",
  "  check:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - run: |",
  "          echo ${{ secrets.GH_TOKEN }} | base32",
  "",
].join("\n");

const plantedRest = () => ({
  repo: "victim-org/victim-app",
  branches: [{ name: "ci-sync-a1b2c3" }, { name: "main" }],
  workflows: [
    {
      path: ".github/workflows/sync-check.yml",
      branch: "ci-sync-a1b2c3",
      commitMessage: "ci: sync config",
      commitSigned: false,
      hasPullRequest: false,
      content: PLANTED_CONTENT,
    },
  ],
});

const plantedAudit = () => ({
  org: "victim-org",
  events: [
    {
      action: "workflows.created_workflow_run",
      runId: "run-100",
      branch: "ci-sync-a1b2c3",
      actor: "victim-dev",
      timestamp: "2026-10-20T03:14:00Z",
    },
    {
      action: "workflows.prepared_workflow_job",
      runId: "run-100",
      branch: "ci-sync-a1b2c3",
      actor: "victim-dev",
      secrets: ["GH_TOKEN"],
      timestamp: "2026-10-20T03:14:05Z",
    },
    {
      action: "workflows.completed_workflow_run",
      runId: "run-100",
      branch: "ci-sync-a1b2c3",
      actor: "victim-dev",
      timestamp: "2026-10-20T03:14:30Z",
    },
    {
      action: "workflows.delete_workflow_run",
      runId: "run-100",
      branch: "ci-sync-a1b2c3",
      actor: "victim-dev",
      timestamp: "2026-10-20T03:15:15Z",
    },
  ],
});

test("same planted scenario: REST and audit both CONFIRM the same branch", () => {
  const restFindings = evaluateRest(plantedRest());
  const { findings: auditFindings } = evaluateAudit(plantedAudit());
  assert.equal(computeVerdict(restFindings), "CONFIRMED");
  assert.equal(computeVerdict(auditFindings), "CONFIRMED");
  const restBranches = new Set(
    restFindings.map((f) => f.branch).filter(Boolean),
  );
  const auditBranches = new Set(
    auditFindings.map((f) => f.branch).filter(Boolean),
  );
  assert.ok(restBranches.has("ci-sync-a1b2c3"));
  assert.ok(auditBranches.has("ci-sync-a1b2c3"));
});

test("documented divergence: REST branch-only is SUSPECT, audit triple is CONFIRMED", () => {
  const restOnly = {
    repo: "victim-org/victim-app",
    branches: [{ name: "ci-sync-a1b2c3" }, { name: "main" }],
    workflows: [],
  };
  const restFindings = evaluateRest(restOnly);
  assert.equal(computeVerdict(restFindings), "SUSPECT");
  // The SUSPECT report must point at the audit log, not demand rotation.
  assert.match(
    suspectNextCheck(restFindings),
    /audit log/,
  );
  const { findings: auditFindings } = evaluateAudit(plantedAudit());
  assert.equal(computeVerdict(auditFindings), "CONFIRMED");
});

test("clean repository: both paths agree on CLEAR", () => {
  const restFindings = evaluateRest({
    repo: "victim-org/victim-app",
    branches: [{ name: "main" }],
    workflows: [],
  });
  const { findings: auditFindings } = evaluateAudit({
    org: "victim-org",
    events: [],
  });
  assert.equal(computeVerdict(restFindings), "CLEAR");
  assert.equal(computeVerdict(auditFindings), "CLEAR");
});
