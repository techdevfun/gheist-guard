import test from "node:test";
import assert from "node:assert/strict";
import { fetchRestInput } from "../dist/rest.js";
import { evaluateRest } from "../dist/rules.js";
import { computeVerdict } from "../dist/verdict.js";

// The live REST adapter is tested with a stubbed global fetch, so no
// network and no token are needed. Each route answers exactly one
// endpoint shape the adapter calls; anything unrouted fails loudly so a
// silent change in the adapter's request set breaks the test instead
// of passing vacuously.

const ok = (data) => ({ ok: true, json: async () => data });
const fail = (status) => ({ ok: false, status, json: async () => ({}) });

const withFetch = async (handler, fn) => {
  const prev = globalThis.fetch;
  globalThis.fetch = handler;
  try {
    return await fn();
  } finally {
    globalThis.fetch = prev;
  }
};

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

const PLANTED_YAML = [
  "name: sync-check",
  "on: [push]",
  "jobs:",
  "  check:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - run: |",
  "          echo ${{ secrets.FAKE_EXAMPLE }} | base32",
  "",
].join("\n");

test("matched-branch workflow is attributed to that branch and CONFIRMS", async () => {
  const handler = async (url) => {
    if (url.includes("/branches?")) {
      return ok([{ name: "main" }, { name: "ci-sync-k7m2p9" }]);
    }
    if (url.includes("/pulls")) return ok([]);
    if (url.includes("/commits?path=")) {
      assert.ok(
        url.includes("sha=ci-sync-k7m2p9"),
        `branch commits must pin sha, got ${url}`,
      );
      return ok([
        {
          sha: "abc123",
          commit: {
            message: "ci: sync config\n\nplanted",
            verification: { verified: false },
          },
        },
      ]);
    }
    if (url.includes("/contents/.github/workflows?")) {
      // Default branch has no workflows directory; the matched branch
      // carries the planted workflow.
      if (url.includes("ref=ci-sync-k7m2p9")) {
        return ok([
          {
            type: "file",
            name: "sync-check.yml",
            path: ".github/workflows/sync-check.yml",
          },
        ]);
      }
      return fail(404);
    }
    if (url.includes("/contents/.github/workflows/sync-check.yml")) {
      assert.ok(
        url.includes("ref=ci-sync-k7m2p9"),
        `branch blob must pin ref, got ${url}`,
      );
      return ok({ content: b64(PLANTED_YAML), encoding: "base64" });
    }
    throw new Error(`unrouted fetch: ${url}`);
  };
  const input = await withFetch(handler, () =>
    fetchRestInput("techdevfun/scratch", {}),
  );
  assert.equal(input.workflows.length, 1);
  assert.equal(input.workflows[0].branch, "ci-sync-k7m2p9");
  assert.equal(input.workflows[0].commitMessage, "ci: sync config");
  assert.equal(input.workflows[0].hasPullRequest, false);
  assert.equal(input.workflows[0].commitSigned, false);
  const findings = evaluateRest(input);
  assert.deepEqual(
    findings.map((f) => f.rule).sort(),
    ["R1", "R2", "R3"],
  );
  assert.equal(computeVerdict(findings), "CONFIRMED");
});

test("default-branch workflow keeps the default attribution", async () => {
  const handler = async (url) => {
    if (url.includes("/branches?")) return ok([{ name: "main" }]);
    if (url.includes("/pulls")) return ok([{ number: 7 }]);
    if (url.includes("/commits?path=")) {
      return ok([
        {
          sha: "def456",
          commit: {
            message: "ci: test",
            verification: { verified: true },
          },
        },
      ]);
    }
    if (url.includes("/contents/.github/workflows?")) {
      return ok([
        { type: "file", name: "ci.yml", path: ".github/workflows/ci.yml" },
      ]);
    }
    if (url.includes("/contents/.github/workflows/ci.yml")) {
      return ok({
        content: b64("name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n"),
        encoding: "base64",
      });
    }
    throw new Error(`unrouted fetch: ${url}`);
  };
  const input = await withFetch(handler, () =>
    fetchRestInput("techdevfun/scratch", {}),
  );
  assert.equal(input.workflows.length, 1);
  assert.equal(input.workflows[0].branch, "default");
  assert.equal(input.workflows[0].hasPullRequest, true);
  assert.deepEqual(evaluateRest(input), []);
  assert.equal(computeVerdict(evaluateRest(input)), "CLEAR");
});
