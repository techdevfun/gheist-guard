import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "dist", "cli.js");
const fx = (name) => path.join(root, "tests", "fixtures", name);

function run(args) {
  const r = spawnSync("node", [cli, ...args], {
    cwd: root,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function stripCheckedAt(text) {
  return text.replace(/"checkedAt": "[^"]+"/g, '"checkedAt": "X"');
}

test("CLI: planted fixture -> CONFIRMED, exit 1, checklist, one stderr line", () => {
  const r = run(["scan", "victim-org/victim-app", "--fixture", fx("planted-rest.json")]);
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stdout);
  assert.equal(report.verdict, "CONFIRMED");
  assert.deepEqual(
    report.findings.map((f) => f.rule).sort(),
    ["R1", "R2", "R3"],
  );
  assert.ok(report.rotateChecklist && report.rotateChecklist.length >= 4);
  assert.match(r.stderr.trim(), /^gheist-guard: verdict=CONFIRMED /);
  assert.equal(r.stderr.trim().split("\n").length, 1);
});

test("CLI: legitimate fixture -> CLEAR, exit 0", () => {
  const r = run(["scan", "some-org/some-app", "--fixture", fx("legit-rest.json")]);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).verdict, "CLEAR");
});

test("CLI: partial fixture -> SUSPECT with next check", () => {
  const r = run(["scan", "some-org/some-app", "--fixture", fx("partial-r1.json")]);
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stdout);
  assert.equal(report.verdict, "SUSPECT");
  assert.equal(report.rotateChecklist, null);
  assert.ok(report.nextCheck && report.nextCheck.includes("audit log"));
});

test("CLI: audit triple fixture -> CONFIRMED via --events", () => {
  const r = run(["audit", "--org", "victim-org", "--events", fx("audit-triple.json")]);
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stdout);
  assert.equal(report.verdict, "CONFIRMED");
  assert.equal(report.path, "audit-log");
  assert.ok(report.rotateChecklist.join("\n").includes("GH_TOKEN"));
});

test("CLI: human format prints Verdict line", () => {
  const r = run([
    "scan",
    "victim-org/victim-app",
    "--fixture",
    fx("planted-rest.json"),
    "--format",
    "human",
  ]);
  assert.match(r.stdout, /^Verdict: CONFIRMED/m);
  assert.match(r.stdout, /Rotate checklist/);
});

test("CLI: checklist re-prints from a saved report without re-scanning", () => {
  const tmp = path.join(os.tmpdir(), "gg-report.json");
  const scan = run(["scan", "victim-org/victim-app", "--fixture", fx("planted-rest.json")]);
  writeFileSync(tmp, scan.stdout);
  const r = run(["checklist", "victim-org/victim-app", "--report", tmp]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Revoke the token of victim-dev/);
  assert.match(r.stdout, /GH_TOKEN/);
  unlinkSync(tmp);
});

test("CLI: checklist on a CLEAR report reports no checklist", () => {
  const tmp = path.join(os.tmpdir(), "gg-report-clear.json");
  const scan = run(["scan", "some-org/some-app", "--fixture", fx("legit-rest.json")]);
  writeFileSync(tmp, scan.stdout);
  const r = run(["checklist", "some-org/some-app", "--report", tmp]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No rotate checklist/);
  unlinkSync(tmp);
});

test("CLI: determinism - two runs byte-identical except checkedAt", () => {
  const a = run(["scan", "victim-org/victim-app", "--fixture", fx("planted-rest.json")]);
  const b = run(["scan", "victim-org/victim-app", "--fixture", fx("planted-rest.json")]);
  assert.equal(stripCheckedAt(a.stdout), stripCheckedAt(b.stdout));
});

test("CLI: allowlist flag turns planted R1 into SKIPPED", () => {
  const r = run([
    "scan",
    "victim-org/victim-app",
    "--fixture",
    fx("planted-rest.json"),
    "--allow-branch-pattern",
    "^ci-sync-.*$",
  ]);
  const report = JSON.parse(r.stdout);
  assert.equal(report.verdict, "CLEAR");
  assert.equal(report.skipped.length, 3);
});

test("CLI: usage errors exit 2", () => {
  assert.equal(run(["scan"]).status, 2);
  assert.equal(run(["frobnicate"]).status, 2);
  assert.equal(run(["audit", "--org", "victim-org"]).status, 2); // no token, no --events
});
