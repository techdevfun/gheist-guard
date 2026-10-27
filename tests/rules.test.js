import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { evaluateRest, isBranchMatch } from "../dist/rules.js";

const dir = path.dirname(fileURLToPath(import.meta.url));
const load = (name) =>
  JSON.parse(readFileSync(path.join(dir, "fixtures", name), "utf8"));
const rulesOf = (findings) => findings.map((f) => f.rule).sort();

test("R1: exactly six [0-9a-z] chars after ci-sync-", () => {
  assert.equal(isBranchMatch("ci-sync-a1b2c3"), true);
  assert.equal(isBranchMatch("ci-sync-config"), true); // 6 letters: matches by design
  assert.equal(isBranchMatch("ci-sync-a1b2"), false); // 4 chars
  assert.equal(isBranchMatch("ci-sync-a1b2c3d"), false); // 7 chars
  assert.equal(isBranchMatch("CI-SYNC-A1B2C3"), false); // case-sensitive
  assert.equal(isBranchMatch("ci-sync-a1b2c3-foo"), false); // suffix
  assert.equal(isBranchMatch("sync-check"), false);
  assert.equal(isBranchMatch("main"), false);
});

test("planted fixture fires R1+R2+R3", () => {
  const findings = evaluateRest(load("planted-rest.json"));
  assert.deepEqual(rulesOf(findings), ["R1", "R2", "R3"]);
  for (const f of findings) {
    assert.ok(f.evidence.length > 0, "every finding quotes evidence");
    assert.ok(!f.evidence.includes("ghp_"), "no secret value in evidence");
  }
});

test("legitimate fixture fires nothing", () => {
  const findings = evaluateRest(load("legit-rest.json"));
  assert.deepEqual(findings, []);
});

test("R1 alone is a partial signal (branch ci-sync-config)", () => {
  const findings = evaluateRest(load("partial-r1.json"));
  assert.deepEqual(rulesOf(findings), ["R1"]);
});

test("GhostAction shape fires R6 only", () => {
  const findings = evaluateRest(load("ghostaction-rest.json"));
  assert.deepEqual(rulesOf(findings), ["R6"]);
  assert.equal(findings[0].severity, "medium");
});

test("sync-host shape fires R1+R7", () => {
  const findings = evaluateRest(load("synchost-rest.json"));
  assert.deepEqual(rulesOf(findings), ["R1", "R7"]);
});

test("base64 of non-secret data does not fire R3", () => {
  const input = {
    repo: "x/y",
    branches: [{ name: "main" }],
    workflows: [
      {
        path: ".github/workflows/encode.yml",
        branch: "main",
        commitMessage: "ci: encode",
        commitSigned: false,
        hasPullRequest: false,
        content: "run: echo build-info | base64\n",
      },
    ],
  };
  assert.deepEqual(evaluateRest(input), []);
});

test("secrets used normally (no encoding, no printenv) do not fire R3", () => {
  const input = {
    repo: "x/y",
    branches: [{ name: "main" }],
    workflows: [
      {
        path: ".github/workflows/publish.yml",
        branch: "main",
        commitMessage: "release",
        commitSigned: true,
        hasPullRequest: true,
        content: "run: npm publish\n  env:\n    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
      },
    ],
  };
  assert.deepEqual(evaluateRest(input), []);
});

test("unreviewed workflow without exfiltration does not fire R6", () => {
  const input = {
    repo: "x/y",
    branches: [{ name: "main" }],
    workflows: [
      {
        path: ".github/workflows/cleanup.yml",
        branch: "main",
        commitMessage: "chore: cleanup",
        commitSigned: false,
        hasPullRequest: false,
        content: "run: rm -rf /tmp/build-cache\n",
      },
    ],
  };
  assert.deepEqual(evaluateRest(input), []);
});

test("signed sync-check with a pull request does not fire R2", () => {
  const input = {
    repo: "x/y",
    branches: [{ name: "ci-sync-a1b2c3" }],
    workflows: [
      {
        path: ".github/workflows/sync-check.yml",
        branch: "ci-sync-a1b2c3",
        commitMessage: "ci: sync config",
        commitSigned: true,
        hasPullRequest: true,
        content: "run: npm test\n",
      },
    ],
  };
  const findings = evaluateRest(input);
  assert.deepEqual(rulesOf(findings), ["R1"]);
});

test("false-positive probe: 24 legitimate branches, 0 CONFIRMED inputs", () => {
  const branches = load("fp-branches.json").branches;
  assert.equal(branches.length, 24);
  const matched = branches.filter(isBranchMatch);
  assert.deepEqual(matched, ["ci-sync-config"]);
});
