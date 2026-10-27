import test from "node:test";
import assert from "node:assert/strict";
import { fetchAuditInput } from "../dist/audit.js";

// The live audit-log fetcher is tested with a stubbed global fetch:
// no org-owner account, no network. The tests pin the exact phrase set
// (a missing phrase is a real detection hole: without the created
// phrase the R4 triple can never form from live data), the paging
// loop, and the defensive secrets mapping.

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

const rowFor = (phrase) => {
  const base = {
    actor: "victim-dev",
    workflow_run_id: "run-1",
    workflow_run_branch: "ci-sync-k7m2p9",
    "@timestamp": "2026-10-20T03:14:00Z",
    workflow_path: ".github/workflows/sync-check.yml",
  };
  if (phrase.includes("created")) {
    return { ...base, action: "workflows.created_workflow_run" };
  }
  if (phrase.includes("completed")) {
    return {
      ...base,
      action: "workflows.completed_workflow_run",
      "@timestamp": "2026-10-20T03:14:30Z",
    };
  }
  if (phrase.includes("delete")) {
    return {
      ...base,
      action: "workflows.delete_workflow_run",
      "@timestamp": "2026-10-20T03:15:15Z",
    };
  }
  return {
    ...base,
    action: "workflows.prepared_workflow_job",
    secrets: ["GH_TOKEN", "AWS_KEY"],
  };
};

test("fetcher queries all four lifecycle phrases and maps prepared secrets", async () => {
  const seen = [];
  const handler = async (url) => {
    seen.push(url);
    const phrase = decodeURIComponent(
      new URL(url).searchParams.get("phrase") ?? "",
    );
    const page = Number(new URL(url).searchParams.get("page") ?? "1");
    if (page > 1) return ok([]);
    return ok([rowFor(phrase)]);
  };
  const input = await withFetch(handler, () =>
    fetchAuditInput("victim-org", "token"),
  );
  for (const phrase of [
    "action:workflows.created_workflow_run",
    "action:workflows.completed_workflow_run",
    "action:workflows.delete_workflow_run",
    "action:workflows.prepared_workflow_job",
  ]) {
    assert.ok(
      seen.some((u) => u.includes(encodeURIComponent(phrase))),
      `missing phrase query: ${phrase}`,
    );
  }
  assert.equal(input.events.length, 4);
  const prepared = input.events.find(
    (e) => e.action === "workflows.prepared_workflow_job",
  );
  assert.deepEqual(prepared.secrets, ["GH_TOKEN", "AWS_KEY"]);
});

test("fetcher pages until an empty page, capped in code at 10", async () => {
  const seen = [];
  const handler = async (url) => {
    seen.push(url);
    const page = Number(new URL(url).searchParams.get("page") ?? "1");
    if (page === 1) return ok([rowFor("created"), rowFor("created")]);
    if (page === 2) return ok([rowFor("created")]);
    return ok([]);
  };
  const input = await withFetch(handler, () =>
    fetchAuditInput("victim-org", "token"),
  );
  // 4 phrases x (2 + 1) rows each.
  assert.equal(input.events.length, 12);
  assert.ok(seen.some((u) => u.includes("page=3")));
});

test("fetcher throws on a non-ok audit-log response", async () => {
  const handler = async () => fail(403);
  await assert.rejects(
    withFetch(handler, () => fetchAuditInput("victim-org", "token")),
    /GitHub audit-log API 403/,
  );
});

test("rows missing optional fields map to undefined, never crash", async () => {
  const handler = async (url) => {
    const page = Number(new URL(url).searchParams.get("page") ?? "1");
    if (page > 1) return ok([]);
    return ok([{ action: "workflows.created_workflow_run" }]);
  };
  const input = await withFetch(handler, () =>
    fetchAuditInput("victim-org", "token"),
  );
  assert.equal(input.events.length, 4);
  for (const e of input.events) {
    assert.equal(e.runId, "");
    assert.equal(e.branch, undefined);
    assert.equal(e.timestamp, "");
    assert.equal(e.secrets, undefined);
  }
});
