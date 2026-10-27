// Report rendering: JSON (default, on stdout) and human-readable text.
// The stderr summary line is always exactly one line, in both formats.

import type { Report } from "./types.js";

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

export function renderHuman(report: Report): string {
  const lines: string[] = [];
  lines.push(`Verdict: ${report.verdict}`);
  lines.push(`Repo: ${report.repo}`);
  lines.push(`Path: ${report.path}`);
  lines.push(
    `Rules: v${report.manifest.rulesVersion}, checked at ${report.manifest.checkedAt}`,
  );
  if (report.findings.length === 0) {
    lines.push("Findings: none");
  } else {
    lines.push("Findings:");
    for (const f of report.findings) {
      lines.push(`  [${f.rule} ${f.severity}] ${f.evidence}`);
    }
  }
  if (report.skipped.length > 0) {
    lines.push("Skipped (allowlisted):");
    for (const s of report.skipped) {
      lines.push(`  [${s.rule}] ${s.evidence} - ${s.reason}`);
    }
  }
  if (report.rotateChecklist) {
    lines.push("Rotate checklist (secret NAMES only, never values):");
    for (const item of report.rotateChecklist) {
      lines.push(`  - ${item}`);
    }
  }
  if (report.nextCheck) {
    lines.push(`Next check: ${report.nextCheck}`);
  }
  return lines.join("\n");
}

export function summaryLine(report: Report): string {
  return (
    `gheist-guard: verdict=${report.verdict} repo=${report.repo} ` +
    `path=${report.path} findings=${report.findings.length} ` +
    `skipped=${report.skipped.length}`
  );
}
