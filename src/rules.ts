// Deterministic rule engine for the Gheist attack shape.
// Every rule is a pure function over its input: no model, no heuristics
// that cannot be stated, no network. A finding always quotes the exact
// matched string and its location; a finding without evidence is a bug.

import {
  type AuditEvent,
  type AuditInput,
  COMPLETE_TO_DELETE_WINDOW_MS,
  type Finding,
  type RestInput,
  type Signal,
} from "./types.js";

export const BRANCH_PATTERN = /^ci-sync-[0-9a-z]{6}$/;

export function isBranchMatch(name: string): boolean {
  return BRANCH_PATTERN.test(name);
}

function mentionsSecret(content: string): boolean {
  return (
    content.includes("secrets.") ||
    content.includes("process.env") ||
    content.includes("${{ secrets")
  );
}

function mentionsEncoding(content: string): string | null {
  if (/\bbase32\b/.test(content)) return "base32";
  if (/\bbase64\b/.test(content)) return "base64";
  return null;
}

function hasDumpIndicator(content: string): string | null {
  if (/\bprintenv\b/.test(content)) return "printenv";
  if (mentionsSecret(content)) {
    const enc = mentionsEncoding(content);
    if (enc) return enc;
  }
  return null;
}

function exfilIndicator(content: string): string | null {
  const ip = content.match(/https?:\/\/\d{1,3}(?:\.\d{1,3}){3}\b/);
  if (ip) return `hardcoded IP URL ${ip[0]}`;
  const pipe = content.match(/\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b/);
  if (pipe) return `pipe-to-shell chain "${pipe[0].trim()}"`;
  if (
    content.includes("fetch-depth: 0") &&
    /(grep|credential)/i.test(content)
  ) {
    return "fetch-depth: 0 plus history/credential grep";
  }
  return null;
}

function syncHostJob(content: string): boolean {
  return (
    /(^|\n)\s{2,}sync-host\s*:/.test(content) ||
    /name:\s*['"]?sync-host['"]?/.test(content)
  );
}

function hostEnumIndicator(content: string): string | null {
  const lower = content.toLowerCase();
  const needles = [
    "/var/run/docker.sock",
    "/proc/",
    "process.env",
    "docker inspect",
    "credential",
  ];
  for (const n of needles) {
    if (lower.includes(n)) return n;
  }
  return null;
}

/** R1..R3, R6, R7 over REST-shaped input. R4/R5 live in audit.ts. */
export function evaluateRest(
  input: RestInput,
  signal: Signal = "rest",
): Finding[] {
  const findings: Finding[] = [];

  for (const b of input.branches) {
    if (isBranchMatch(b.name)) {
      findings.push({
        rule: "R1",
        name: "branch-pattern",
        severity: "high",
        evidence: `branch ${b.name} matches ^ci-sync-[0-9a-z]{6}$`,
        signal,
        branch: b.name,
      });
    }
  }

  for (const w of input.workflows) {
    if (
      w.path === ".github/workflows/sync-check.yml" &&
      w.commitMessage === "ci: sync config" &&
      !w.commitSigned &&
      !w.hasPullRequest
    ) {
      findings.push({
        rule: "R2",
        name: "workflow-identity",
        severity: "high",
        evidence:
          `workflow ${w.path} on branch ${w.branch} added with commit ` +
          `"ci: sync config", unsigned push, no pull request`,
        signal,
        branch: w.branch,
        workflowPath: w.path,
      });
    }

    const dump = hasDumpIndicator(w.content);
    if (dump) {
      findings.push({
        rule: "R3",
        name: "dump-content",
        severity: "high",
        evidence:
          `workflow ${w.path} on branch ${w.branch} prints environment or ` +
          `secrets through ${dump}`,
        signal,
        branch: w.branch,
        workflowPath: w.path,
      });
    }

    if (!w.hasPullRequest) {
      const exfil = exfilIndicator(w.content);
      if (exfil) {
        findings.push({
          rule: "R6",
          name: "generic-unreviewed-workflow",
          severity: "medium",
          evidence:
            `workflow ${w.path} on branch ${w.branch} changed without a ` +
            `pull request or review and carries exfiltration indicator: ${exfil}`,
          signal,
          branch: w.branch,
          workflowPath: w.path,
        });
      }
    }

    if (syncHostJob(w.content)) {
      const indicator = hostEnumIndicator(w.content);
      if (indicator) {
        findings.push({
          rule: "R7",
          name: "self-hosted-variant",
          severity: "high",
          evidence:
            `workflow ${w.path} on branch ${w.branch} defines a sync-host ` +
            `job with host enumeration indicator "${indicator}"`,
          signal,
          branch: w.branch,
          workflowPath: w.path,
        });
      }
    }
  }

  return findings;
}

/**
 * R1 (from event branch names), R4 (complete->delete within 60s on a
 * matched branch), R5 (user agent "gheist") over audit-log events.
 * R4 requires a matched branch by definition: the lifecycle triple alone
 * on an unrelated branch is not a Gheist finding.
 */
export function evaluateAudit(input: AuditInput): {
  findings: Finding[];
  preparedSecrets: string[];
  actors: string[];
} {
  const findings: Finding[] = [];
  const preparedSecrets: string[] = [];
  const actors: string[] = [];
  const matchedBranches = new Set<string>();
  const r5Seen = new Set<string>(); // one R5 finding per run, not per event

  for (const e of input.events) {
    if (e.branch && isBranchMatch(e.branch) && !matchedBranches.has(e.branch)) {
      matchedBranches.add(e.branch);
      findings.push({
        rule: "R1",
        name: "branch-pattern",
        severity: "high",
        evidence: `branch ${e.branch} matches ^ci-sync-[0-9a-z]{6}$ (audit-log event)`,
        signal: "audit-log",
        branch: e.branch,
      });
    }
    if (e.action === "workflows.prepared_workflow_job" && e.secrets) {
      for (const s of e.secrets) {
        if (!preparedSecrets.includes(s)) preparedSecrets.push(s);
      }
    }
    if (e.actor && !actors.includes(e.actor)) actors.push(e.actor);
    if (e.userAgent === "gheist" && !r5Seen.has(e.runId)) {
      r5Seen.add(e.runId);
      findings.push({
        rule: "R5",
        name: "tool-fingerprint",
        severity: "high",
        evidence: `audit-log event with user agent "gheist" (run ${e.runId}` +
          (e.branch ? `, branch ${e.branch}` : "") +
          `)`,
        signal: "audit-log",
        branch: e.branch,
      });
    }
  }

  // Pair lifecycles per run id: created -> completed -> deleted.
  const byRun = new Map<string, AuditEvent[]>();
  for (const e of input.events) {
    const list = byRun.get(e.runId) ?? [];
    list.push(e);
    byRun.set(e.runId, list);
  }
  for (const [runId, events] of byRun) {
    const created = events.find(
      (e) => e.action === "workflows.created_workflow_run",
    );
    const completed = events.find(
      (e) => e.action === "workflows.completed_workflow_run",
    );
    const deleted = events.find(
      (e) => e.action === "workflows.delete_workflow_run",
    );
    if (!created || !completed || !deleted) continue;
    const branch = completed.branch ?? created.branch ?? deleted.branch;
    if (!branch || !isBranchMatch(branch)) continue;
    const deltaMs =
      Date.parse(deleted.timestamp) - Date.parse(completed.timestamp);
    if (deltaMs >= 0 && deltaMs <= COMPLETE_TO_DELETE_WINDOW_MS) {
      findings.push({
        rule: "R4",
        name: "run-lifecycle",
        severity: "high",
        evidence:
          `workflow run ${runId} on branch ${branch} completed then deleted ` +
          `within ${Math.round(deltaMs / 1000)}s (window 60s)`,
        signal: "audit-log",
        branch,
      });
    }
  }

  return { findings, preparedSecrets, actors };
}
