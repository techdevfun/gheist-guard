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
// with R2/R3 into CONFIRMED on the live path.

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
  const branches = (await getJson(
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
      files = (await getJson(
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
  const rows = (await getJson(
    `${API}/orgs/${org}/repos?per_page=100`,
    opts.token,
  )) as { full_name: string }[];
  return rows.map((r) => r.full_name);
}
