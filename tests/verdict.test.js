import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { evaluateRest } from "../dist/rules.js";
import {
  applyAllowlist,
  buildChecklist,
  buildReport,
  computeVerdict,
} from "../dist/verdict.js";

const dir = path.dirname(fileURLToPath(import.meta.url));
const load = (name) =>
  JSON.parse(readFileSync(path.join(dir, "fixtures", name), "utf8"));

test("verdict: R1+R2+R3 is CONFIRMED with a rotate checklist", () => {
  const input = load("planted-rest.json");
  const findings = evaluateRest(input);
  const report = buildReport({
    repo: input.repo,
    path: "rest",
    findings,
    skipped: [],
    matchedBranches: ["ci-sync-a1b2c3"],
    pusher: input.pusher,
    inventory: input.secretInventory,
  });
  assert.equal(report.verdict, "CONFIRMED");
  assert.ok(report.rotateChecklist);
  const text = report.rotateChecklist.join("\n");
  assert.match(text, /Revoke the token of victim-dev/);
  assert.match(text, /GH_TOKEN/);
  assert.match(text, /AWS_KEY/);
  assert.match(text, /OIDC roles/);
  assert.match(text, /infostealer/);
  assert.equal(report.nextCheck, null);
});

test("verdict: R1+R7 is CONFIRMED", () => {
  const findings = evaluateRest(load("synchost-rest.json"));
  assert.equal(computeVerdict(findings), "CONFIRMED");
});

test("verdict: R1 alone and R6 alone are SUSPECT with a next check", () => {
  for (const name of ["partial-r1.json", "ghostaction-rest.json"]) {
    const findings = evaluateRest(load(name));
    const report = buildReport({
      repo: "x/y",
      path: "rest",
      findings,
      skipped: [],
      matchedBranches: [],
    });
    assert.equal(report.verdict, "SUSPECT");
    assert.equal(report.rotateChecklist, null);
    assert.ok(report.nextCheck && report.nextCheck.length > 0);
  }
});

test("verdict: no findings is CLEAR", () => {
  assert.equal(computeVerdict([]), "CLEAR");
});

test("allowlist: allowed branch is SKIPPED with reason, never dropped silently", () => {
  const input = load("planted-rest.json");
  const findings = evaluateRest(input);
  const { kept, skipped } = applyAllowlist(findings, {
    branchPatterns: [/^ci-sync-.*$/],
    workflows: [],
  });
  // All three findings carry the matched branch, so all three are skipped
  // with a reason; none is silently dropped.
  assert.equal(skipped.length, 3);
  assert.deepEqual(
    skipped.map((s) => s.rule).sort(),
    ["R1", "R2", "R3"],
  );
  assert.ok(skipped.every((s) => /allow-branch-pattern/.test(s.reason)));
  assert.equal(kept.length, 0);
  assert.equal(computeVerdict(kept), "CLEAR");
});

test("allowlist: allowing only the workflow leaves R1 as SUSPECT", () => {
  const input = load("planted-rest.json");
  const findings = evaluateRest(input);
  const { kept, skipped } = applyAllowlist(findings, {
    branchPatterns: [],
    workflows: [".github/workflows/sync-check.yml"],
  });
  assert.deepEqual(
    kept.map((f) => f.rule),
    ["R1"],
  );
  assert.equal(skipped.length, 2);
  assert.equal(computeVerdict(kept), "SUSPECT");
});

test("checklist merges prepared names and inventory names, sorted, no values", () => {
  const list = buildChecklist({
    matchedBranches: ["ci-sync-a1b2c3"],
    pusher: "victim-dev",
    preparedSecrets: ["GH_TOKEN"],
    inventory: { repo: ["AWS_KEY", "GH_TOKEN"], org: [], env: {} },
  });
  const namesLine = list.find((l) => l.startsWith("Rotate repository secrets"));
  assert.equal(namesLine, "Rotate repository secrets (names only): AWS_KEY, GH_TOKEN");
  assert.ok(!list.join("\n").includes("ghp_"));
});

test("checklist without any names still orders rotation first", () => {
  const list = buildChecklist({
    matchedBranches: ["ci-sync-a1b2c3"],
    preparedSecrets: [],
  });
  assert.match(list[1], /Rotate every secret the repository could read/);
});
