// GitHub REST adapter (read-only). Used by `scan <owner/repo>`.
// Endpoints used: list branches, list .github/workflows contents, fetch a
// file blob, list commits touching a path, list pull requests containing a
// commit. No write endpoint is called anywhere in this file.
// Pull-request association is an approximation, documented in the README:
// a workflow commit with an associated pull request is treated as reviewed;
// a commit with no associated pull request is treated as unreviewed.
// Workflow coverage: the default branch AND every branch matching the
// Gheist branch pattern. A plant that lives only on a ci-sync branch is
// invisible to a default-branch-only listing, so matched branches are
// read explicitly via ?ref=<branch>. A workflow found on a matched
// branch is attributed to that branch, which is what lets R1 combine
// with R2/R3 into CONFIRMED on the live path. List endpoints are fully
// paginated (Link rel="next"): a single-page read would silently drop
// branches, workflows, or repositories past the first 100 and could
// report a false CLEAR.

import type { RestInput, WorkflowInput } from "./types.js";
import { isBranchMatch } from "./rules.js";

const API = "https://api.github.com";

export interface RestOptions {
  token?: string;
}

async function getJson(
  url: string,
  token?: string,
): Promise<unknown> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "gheist-guard",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status} for ${url}`);
  }
  return res.json() as Promise<unknown>;
}

/** Extract the `rel="next"` URL from a GitHub `Link` header, if any. */
function parseNextLink(linkHeader: string | null | undefined): string | null {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (m) return m[1];
  }
  return null;
}

/**
 * Fetch a paginated list endpoint, following `rel="next"` until the
 * list is exhausted. List endpoints cap at 100 items per page, so a
 * single-page read silently drops everything past the first page:
 * a planted branch past branch 100 would be missed entirely and the
 * scan would report a false CLEAR. A visited-URL set guards against
 * a looping `Link` header; it never truncates a legitimate list.
 */
async function getJsonPaged(
  url: string,
  token?: string,
): Promise<unknown[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "gheist-guard",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const out: unknown[] = [];
  const seen = new Set<string>();
  let next: string | null = url;
  while (next) {
    if (seen.has(next)) {
      throw new Error(`GitHub API paging loop at ${next}`);
    }
    seen.add(next);
    const res = await fetch(next, { headers });
    if (!res.ok) {
      throw new Error(`GitHub API ${res.status} for ${next}`);
    }
    const data = (await res.json()) as unknown;
    if (!Array.isArray(data)) {
      throw new Error(`GitHub API returned a non-list for ${next}`);
    }
    out.push(...data);
    next = parseNextLink(res.headers?.get?.("link"));
  }
  return out;
}

interface BranchRow {
  name: string;
}

interface ContentRow {
  type: string;
  name: string;
  path: string;
}

interface CommitRow {
  sha: string;
  commit: { message: string; verification?: { verified?: boolean } };
}

interface PullRow {
  number: number;
}

export async function fetchRestInput(
  ownerRepo: string,
  opts: RestOptions = {},
): Promise<RestInput> {
  const [owner, repo] = ownerRepo.split("/");
  if (!owner || !repo) {
    throw new Error(`expected <owner/repo>, got "${ownerRepo}"`);
  }
  const branches = (await getJsonPaged(
    `${API}/repos/${owner}/${repo}/branches?per_page=100`,
    opts.token,
  )) as BranchRow[];

  const collectWorkflows = async (
    ref: string | undefined,
    branchLabel: string,
  ): Promise<WorkflowInput[]> => {
    const refQuery = ref ? `&ref=${encodeURIComponent(ref)}` : "";
    let files: ContentRow[] = [];
    try {
      files = (await getJsonPaged(
        `${API}/repos/${owner}/${repo}/contents/.github/workflows?per_page=100${refQuery}`,
        opts.token,
      )) as ContentRow[];
    } catch {
      files = []; // no workflows directory on this ref: no workflows
    }
    const out: WorkflowInput[] = [];
    for (const f of files.filter((x) => x.type === "file")) {
      const blob = (await getJson(
        `${API}/repos/${owner}/${repo}/contents/${f.path}${ref ? `?ref=${encodeURIComponent(ref)}` : ""}`,
        opts.token,
      )) as { content?: string; encoding?: string };
      const content =
        blob.encoding === "base64" && blob.content
          ? Buffer.from(blob.content, "base64").toString("utf8")
          : "";
      const commits = (await getJson(
        `${API}/repos/${owner}/${repo}/commits?path=${encodeURIComponent(f.path)}&per_page=1${ref ? `&sha=${encodeURIComponent(ref)}` : ""}`,
        opts.token,
      )) as CommitRow[];
      const head = commits[0];
      let hasPullRequest = false;
      if (head) {
        const pulls = (await getJson(
          `${API}/repos/${owner}/${repo}/commits/${head.sha}/pulls`,
          opts.token,
        )) as PullRow[];
        hasPullRequest = pulls.length > 0;
      }
      out.push({
        path: f.path,
        branch: branchLabel,
        commitMessage: head ? head.commit.message.split("\n")[0] : "",
        commitSigned: head?.commit.verification?.verified ?? false,
        hasPullRequest,
        content,
      });
    }
    return out;
  };

  const workflows: WorkflowInput[] = [];
  workflows.push(...(await collectWorkflows(undefined, "default")));
  for (const b of branches) {
    if (isBranchMatch(b.name)) {
      workflows.push(...(await collectWorkflows(b.name, b.name)));
    }
  }

  return {
    repo: ownerRepo,
    branches: branches.map((b) => ({ name: b.name })),
    workflows,
  };
}

/** List repository names for `scan --org <org>` (public listing only). */
export async function listOrgRepos(
  org: string,
  opts: RestOptions = {},
): Promise<string[]> {
  const rows = (await getJsonPaged(
    `${API}/orgs/${org}/repos?per_page=100`,
    opts.token,
  )) as { full_name: string }[];
  return rows.map((r) => r.full_name);
}
