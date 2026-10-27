// Verdict computation, allowlist handling, and the rotate checklist.
// Verdict rule (blueprint 5.2): CONFIRMED = R1 plus any of R2, R3, R4, R5,
// R7. Any other fired rule set is SUSPECT; no findings is CLEAR.
// A partial-signal finding is SUSPECT, never silently CLEAR, never
// CONFIRMED without the full documented combination.

import {
  type Finding,
  type Report,
  RULES_VERSION,
  type SkippedItem,
  type Verdict,
} from "./types.js";

export interface Allowlist {
  branchPatterns: RegExp[];
  workflows: string[];
}

export function applyAllowlist(
  findings: Finding[],
  allow: Allowlist,
): { kept: Finding[]; skipped: SkippedItem[] } {
  const kept: Finding[] = [];
  const skipped: SkippedItem[] = [];
  for (const f of findings) {
    let reason: string | null = null;
    if (
      f.branch &&
      allow.branchPatterns.some((re) => re.test(f.branch as string))
    ) {
      reason = `branch ${f.branch} matches --allow-branch-pattern`;
    } else if (
      f.workflowPath &&
      allow.workflows.includes(f.workflowPath)
    ) {
      reason = `workflow ${f.workflowPath} matches --allow-workflow`;
    }
    if (reason) {
      skipped.push({ rule: f.rule, evidence: f.evidence, reason });
    } else {
      kept.push(f);
    }
  }
  return { kept, skipped };
}

export function computeVerdict(findings: Finding[]): Verdict {
  if (findings.length === 0) return "CLEAR";
  const fired = new Set(findings.map((f) => f.rule));
  const confirmed =
    fired.has("R1") &&
    (fired.has("R2") ||
      fired.has("R3") ||
      fired.has("R4") ||
      fired.has("R5") ||
      fired.has("R7"));
  return confirmed ? "CONFIRMED" : "SUSPECT";
}

export function suspectNextCheck(findings: Finding[]): string | null {
  if (findings.some((f) => f.rule === "R1")) {
    return (
      "Branch pattern alone is not confirmation. Next check: query the " +
      "organization audit log for the created/completed/deleted run triple " +
      "on this branch, and grep CloudTrail AssumeRoleWithWebIdentity events " +
      "for an OIDC subject carrying this branch ref."
    );
  }
  if (findings.some((f) => f.rule === "R6")) {
    return (
      "Unreviewed workflow with an exfiltration indicator is not " +
      "confirmation. Next check: review the workflow change, confirm whether " +
      "the exfiltration target is internal and expected, and check who " +
      "pushed it and from which machine."
    );
  }
  return (
    "Partial signal only. Next check: review the quoted evidence and " +
    "confirm whether the remaining half of the documented pattern exists."
  );
}

/**
 * Ordered rotate list. Lists secret NAMES only - this function never sees
 * a value, and neither does any caller: the data model carries names.
 */
export function buildChecklist(opts: {
  matchedBranches: string[];
  pusher?: string;
  preparedSecrets: string[];
  inventory?: {
    repo?: string[];
    org?: string[];
    env?: Record<string, string[]>;
  };
}): string[] {
  const lines: string[] = [];
  const branches = opts.matchedBranches.join(", ") || "(unknown branch)";
  if (opts.pusher) {
    lines.push(`Revoke the token of ${opts.pusher} (pusher of ${branches})`);
  } else {
    lines.push(`Revoke the token that pushed ${branches}`);
  }
  const names = new Set<string>(opts.preparedSecrets);
  if (opts.inventory) {
    for (const n of opts.inventory.repo ?? []) names.add(n);
    for (const n of opts.inventory.org ?? []) names.add(n);
    for (const envNames of Object.values(opts.inventory.env ?? {})) {
      for (const n of envNames) names.add(n);
    }
  }
  if (names.size > 0) {
    lines.push(
      `Rotate repository secrets (names only): ${[...names].sort().join(", ")}`,
    );
  } else {
    lines.push(
      "Rotate every secret the repository could read (no secret-name " +
        "inventory was available; list them from repository, organization, " +
        "and environment settings)",
    );
  }
  lines.push(
    `Check OIDC roles assumable from ref ${branches} (CloudTrail ` +
      `AssumeRoleWithWebIdentity events carrying this ref)`,
  );
  lines.push(
    "Check the pushing account's machine for infostealer compromise " +
      "(the documented token-theft source) before issuing a replacement token",
  );
  return lines;
}

export function buildReport(opts: {
  repo: string;
  path: "rest" | "audit-log";
  findings: Finding[];
  skipped: SkippedItem[];
  matchedBranches: string[];
  pusher?: string;
  preparedSecrets?: string[];
  inventory?: {
    repo?: string[];
    org?: string[];
    env?: Record<string, string[]>;
  };
  checkedAt?: string;
}): Report {
  const verdict = computeVerdict(opts.findings);
  return {
    verdict,
    repo: opts.repo,
    path: opts.path,
    findings: opts.findings,
    skipped: opts.skipped,
    manifest: {
      rulesVersion: RULES_VERSION,
      checkedAt: opts.checkedAt ?? new Date().toISOString(),
    },
    rotateChecklist:
      verdict === "CONFIRMED"
        ? buildChecklist({
            matchedBranches: opts.matchedBranches,
            pusher: opts.pusher,
            preparedSecrets: opts.preparedSecrets ?? [],
            inventory: opts.inventory,
          })
        : null,
    nextCheck: verdict === "SUSPECT" ? suspectNextCheck(opts.findings) : null,
  };
}
