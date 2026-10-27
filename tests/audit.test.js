import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { evaluateAudit } from "../dist/rules.js";
import { computeVerdict } from "../dist/verdict.js";

const dir = path.dirname(fileURLToPath(import.meta.url));
const load = (name) =>
  JSON.parse(readFileSync(path.join(dir, "fixtures", name), "utf8"));
const rulesOf = (findings) => findings.map((f) => f.rule).sort();

test("audit triple in 45s fires R1+R4 and collects prepared secret names", () => {
  const { findings, preparedSecrets, actors } = evaluateAudit(
    load("audit-triple.json"),
  );
  assert.deepEqual(rulesOf(findings), ["R1", "R4"]);
  assert.deepEqual(preparedSecrets.sort(), ["AWS_KEY", "GH_TOKEN"]);
  assert.deepEqual(actors, ["victim-dev"]);
  assert.equal(computeVerdict(findings), "CONFIRMED");
});

test("audit user-agent gheist fires R1+R5", () => {
  const { findings } = evaluateAudit(load("audit-ua.json"));
  assert.deepEqual(rulesOf(findings), ["R1", "R5"]);
  assert.equal(computeVerdict(findings), "CONFIRMED");
});

test("complete->delete in 300s does not fire R4 (window is 60s)", () => {
  const { findings } = evaluateAudit(load("audit-slow.json"));
  assert.deepEqual(rulesOf(findings), ["R1"]);
  assert.equal(computeVerdict(findings), "SUSPECT");
});

test("complete->delete boundary: 60s fires, 61s does not", () => {
  const base = (deletedAt) => ({
    org: "victim-org",
    events: [
      {
        action: "workflows.created_workflow_run",
        runId: "r",
        branch: "ci-sync-a1b2c3",
        timestamp: "2026-10-20T03:14:00Z",
      },
      {
        action: "workflows.completed_workflow_run",
        runId: "r",
        branch: "ci-sync-a1b2c3",
        timestamp: "2026-10-20T03:14:30Z",
      },
      {
        action: "workflows.delete_workflow_run",
        runId: "r",
        branch: "ci-sync-a1b2c3",
        timestamp: deletedAt,
      },
    ],
  });
  assert.ok(
    evaluateAudit(base("2026-10-20T03:15:30Z")).findings.some(
      (f) => f.rule === "R4",
    ),
  );
  assert.ok(
    !evaluateAudit(base("2026-10-20T03:15:31Z")).findings.some(
      (f) => f.rule === "R4",
    ),
  );
});

test("lifecycle triple on a non-matching branch does not fire R4", () => {
  const input = {
    org: "victim-org",
    events: [
      {
        action: "workflows.created_workflow_run",
        runId: "r",
        branch: "main",
        timestamp: "2026-10-20T03:14:00Z",
      },
      {
        action: "workflows.completed_workflow_run",
        runId: "r",
        branch: "main",
        timestamp: "2026-10-20T03:14:30Z",
      },
      {
        action: "workflows.delete_workflow_run",
        runId: "r",
        branch: "main",
        timestamp: "2026-10-20T03:15:00Z",
      },
    ],
  };
  assert.deepEqual(evaluateAudit(input).findings, []);
});

test("created event alone is a partial signal (R1 only)", () => {
  const { findings } = evaluateAudit(load("audit-partial.json"));
  assert.deepEqual(rulesOf(findings), ["R1"]);
  assert.equal(computeVerdict(findings), "SUSPECT");
});

// --- Edge cases: the evaluator must be order-independent, duplicate-
// safe, and total over malformed input. None of these may crash, and
// none may invent a finding the evidence does not support.

const triple = (overrides = {}) => {
  const base = [
    {
      action: "workflows.created_workflow_run",
      runId: "r",
      branch: "ci-sync-a1b2c3",
      timestamp: "2026-10-20T03:14:00Z",
    },
    {
      action: "workflows.completed_workflow_run",
      runId: "r",
      branch: "ci-sync-a1b2c3",
      timestamp: "2026-10-20T03:14:30Z",
    },
    {
      action: "workflows.delete_workflow_run",
      runId: "r",
      branch: "ci-sync-a1b2c3",
      timestamp: "2026-10-20T03:15:15Z",
    },
  ];
  return { org: "victim-org", events: overrides(base) };
};

test("out-of-order events still pair into one R4 (find, not sequence)", () => {
  const { findings } = evaluateAudit(
    triple((ev) => [ev[2], ev[0], ev[1]]),
  );
  assert.equal(findings.filter((f) => f.rule === "R4").length, 1);
});

test("duplicated triple events still yield exactly one R4", () => {
  const { findings } = evaluateAudit(
    triple((ev) => [...ev, ...ev]),
  );
  assert.equal(findings.filter((f) => f.rule === "R4").length, 1);
});

test("deleted before completed is not a lifecycle (negative delta)", () => {
  const { findings } = evaluateAudit(
    triple((ev) => [
      ev[0],
      { ...ev[1], timestamp: "2026-10-20T03:16:00Z" },
      { ...ev[2], timestamp: "2026-10-20T03:15:00Z" },
    ]),
  );
  assert.ok(!findings.some((f) => f.rule === "R4"));
});

test("invalid timestamp never fires R4 and never throws", () => {
  const { findings } = evaluateAudit(
    triple((ev) => [{ ...ev[1], timestamp: "not-a-date" }, ev[0], ev[2]]),
  );
  assert.ok(!findings.some((f) => f.rule === "R4"));
});

test("branch falls back to the created event when others omit it", () => {
  const { findings } = evaluateAudit(
    triple((ev) => [
      ev[0],
      { ...ev[1], branch: undefined },
      { ...ev[2], branch: undefined },
    ]),
  );
  const r4 = findings.find((f) => f.rule === "R4");
  assert.ok(r4);
  assert.equal(r4.branch, "ci-sync-a1b2c3");
});

test("interleaved runs: only the in-window triple fires R4", () => {
  const slow = triple((ev) =>
    ev.map((e) => ({
      ...e,
      runId: "slow",
      branch: "ci-sync-d4e5f6",
      timestamp:
        e.action === "workflows.delete_workflow_run"
          ? "2026-10-20T03:20:00Z"
          : e.timestamp,
    })),
  ).events;
  const { findings } = evaluateAudit({
    org: "victim-org",
    events: [...triple((ev) => ev).events, ...slow],
  });
  const r4s = findings.filter((f) => f.rule === "R4");
  assert.equal(r4s.length, 1);
  assert.equal(r4s[0].branch, "ci-sync-a1b2c3");
});

test("prepared secret names deduplicate across events", () => {
  const { preparedSecrets } = evaluateAudit({
    org: "victim-org",
    events: [
      {
        action: "workflows.prepared_workflow_job",
        runId: "r1",
        branch: "ci-sync-a1b2c3",
        secrets: ["GH_TOKEN", "AWS_KEY"],
        timestamp: "2026-10-20T03:14:05Z",
      },
      {
        action: "workflows.prepared_workflow_job",
        runId: "r2",
        branch: "ci-sync-a1b2c3",
        secrets: ["GH_TOKEN", "DB_PASS"],
        timestamp: "2026-10-20T03:14:06Z",
      },
    ],
  });
  assert.deepEqual(preparedSecrets.sort(), [
    "AWS_KEY",
    "DB_PASS",
    "GH_TOKEN",
  ]);
});

test("empty event list is CLEAR, not an error", () => {
  const { findings } = evaluateAudit({ org: "victim-org", events: [] });
  assert.deepEqual(findings, []);
  assert.equal(computeVerdict(findings), "CLEAR");
});
