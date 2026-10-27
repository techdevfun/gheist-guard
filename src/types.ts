// Shared input/output shapes for gheist-guard.
// The tool never carries a secret VALUE anywhere in its data model:
// only secret NAMES (from an audit-log prepared event or a name inventory).
// That makes "names only, never values" true by construction, not by care.

export type Signal = "rest" | "audit-log";
export type Verdict = "CLEAR" | "SUSPECT" | "CONFIRMED";

export interface Finding {
  rule: string; // "R1".."R7"
  name: string;
  severity: "high" | "medium";
  evidence: string; // exact matched string + location, never a secret value
  signal: Signal;
  branch?: string;
  workflowPath?: string;
}

export interface SkippedItem {
  rule: string;
  evidence: string;
  reason: string;
}

export interface BranchInput {
  name: string;
}

export interface WorkflowInput {
  path: string;
  branch: string;
  commitMessage: string;
  commitSigned: boolean;
  hasPullRequest: boolean;
  content: string;
  author?: string;
}

export interface SecretInventory {
  repo?: string[];
  org?: string[];
  env?: Record<string, string[]>;
}

export interface RestInput {
  repo: string;
  branches: BranchInput[];
  workflows: WorkflowInput[];
  secretInventory?: SecretInventory;
  pusher?: string;
}

export type AuditAction =
  | "workflows.created_workflow_run"
  | "workflows.completed_workflow_run"
  | "workflows.delete_workflow_run"
  | "workflows.prepared_workflow_job"
  | string;

export interface AuditEvent {
  action: AuditAction;
  runId: string;
  branch?: string;
  actor?: string;
  userAgent?: string;
  timestamp: string; // ISO 8601
  workflowPath?: string;
  secrets?: string[]; // secret NAMES provided to the job, never values
}

export interface AuditInput {
  org: string;
  events: AuditEvent[];
}

export interface Report {
  verdict: Verdict;
  repo: string;
  path: "rest" | "audit-log";
  findings: Finding[];
  skipped: SkippedItem[];
  manifest: { rulesVersion: string; checkedAt: string };
  rotateChecklist: string[] | null;
  nextCheck: string | null;
}

export const RULES_VERSION = "2026.10";
export const COMPLETE_TO_DELETE_WINDOW_MS = 60_000;
