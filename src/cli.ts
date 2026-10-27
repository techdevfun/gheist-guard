// gheist-guard CLI: scan | audit | checklist.
// Read-only by default. Exit 0 on CLEAR, exit 1 on SUSPECT or CONFIRMED,
// exit 2 on usage or API errors. One stderr summary line, always.
// Secret VALUES never appear in any output: the data model carries names
// only, and the checklist prints names only.

import { readFileSync } from "node:fs";
import { evaluateAudit, evaluateRest } from "./rules.js";
import { renderHuman, renderJson, summaryLine } from "./report.js";
import { fetchRestInput, listOrgRepos } from "./rest.js";
import { fetchAuditInput } from "./audit.js";
import {
  applyAllowlist,
  buildReport,
  type Allowlist,
} from "./verdict.js";
import type {
  AuditEvent,
  AuditInput,
  Report,
  RestInput,
} from "./types.js";

const VERSION = "0.1.1";

const HELP = `gheist-guard ${VERSION} - behavioral detector for the Gheist planted-workflow attack shape.

Usage:
  gheist-guard scan <owner/repo> [--fixture <file>] [--token <token>]
      [--allow-branch-pattern <regex>]... [--allow-workflow <path>]...
      [--format json|human]
  gheist-guard scan --org <org> [--token <token>] [--format json|human]
  gheist-guard audit --org <org> [--events <file>] [--token <token>]
      [--format json|human]
  gheist-guard checklist <owner/repo> --report <file>
  gheist-guard --help | --version

Exit codes: 0 = CLEAR, 1 = SUSPECT or CONFIRMED, 2 = usage or API error.
The GitHub token may also come from GITHUB_TOKEN. The audit-log live path
requires an organization-owner token; without one, use --events with
recorded audit-log payloads (fixture-verified path, see README).
The tool never deletes, rotates, or revokes anything, and never prints a
secret value: the rotate checklist lists secret NAMES only.`;

interface Flags {
  positional: string[];
  fixture?: string;
  events?: string;
  report?: string;
  org?: string;
  token?: string;
  format: "json" | "human";
  allowBranch: string[];
  allowWorkflow: string[];
}

function parseArgs(argv: string[]): { command: string; flags: Flags } {
  const args = [...argv];
  let command = "";
  if (args[0] && !args[0].startsWith("-")) {
    command = args.shift() as string;
  }
  const flags: Flags = {
    positional: [],
    format: "json",
    allowBranch: [],
    allowWorkflow: [],
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const next = () => {
      const v = args[++i];
      if (v === undefined) throw new Error(`missing value for ${a}`);
      return v;
    };
    if (a === "--fixture") flags.fixture = next();
    else if (a === "--events") flags.events = next();
    else if (a === "--report") flags.report = next();
    else if (a === "--org") flags.org = next();
    else if (a === "--token") flags.token = next();
    else if (a === "--format") {
      const f = next();
      if (f !== "json" && f !== "human") {
        throw new Error(`--format must be json or human, got "${f}"`);
      }
      flags.format = f;
    } else if (a === "--allow-branch-pattern") flags.allowBranch.push(next());
    else if (a === "--allow-workflow") flags.allowWorkflow.push(next());
    else if (a.startsWith("-")) throw new Error(`unknown flag ${a}`);
    else flags.positional.push(a);
  }
  return { command, flags };
}

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function toAllowlist(flags: Flags): Allowlist {
  return {
    branchPatterns: flags.allowBranch.map((p) => new RegExp(p)),
    workflows: flags.allowWorkflow,
  };
}

function emit(report: Report, format: "json" | "human"): number {
  console.log(format === "human" ? renderHuman(report) : renderJson(report));
  console.error(summaryLine(report));
  return report.verdict === "CLEAR" ? 0 : 1;
}

function matchedBranches(findings: { branch?: string }[]): string[] {
  const out: string[] = [];
  for (const f of findings) {
    if (f.branch && !out.includes(f.branch)) out.push(f.branch);
  }
  return out;
}

async function runScan(flags: Flags): Promise<number> {
  const token = flags.token ?? process.env.GITHUB_TOKEN;
  const allow = toAllowlist(flags);

  if (flags.org) {
    const repos = await listOrgRepos(flags.org, { token });
    const reports: Report[] = [];
    let code = 0;
    for (const repo of repos) {
      const input = await fetchRestInput(repo, { token });
      const { kept, skipped } = applyAllowlist(
        evaluateRest(input),
        allow,
      );
      const report = buildReport({
        repo,
        path: "rest",
        findings: kept,
        skipped,
        matchedBranches: matchedBranches(kept),
        pusher: input.pusher,
        inventory: input.secretInventory,
      });
      reports.push(report);
      if (report.verdict !== "CLEAR") code = 1;
    }
    console.log(JSON.stringify(reports, null, 2));
    console.error(
      `gheist-guard: org=${flags.org} repos=${reports.length} ` +
        `non-clear=${reports.filter((r) => r.verdict !== "CLEAR").length}`,
    );
    return code;
  }

  const target = flags.positional[0];
  if (!target) throw new Error("scan requires <owner/repo> or --org <org>");
  let input: RestInput;
  if (flags.fixture) {
    input = loadJson(flags.fixture) as RestInput;
  } else {
    input = await fetchRestInput(target, { token });
  }
  const { kept, skipped } = applyAllowlist(evaluateRest(input), allow);
  const report = buildReport({
    repo: input.repo || target,
    path: "rest",
    findings: kept,
    skipped,
    matchedBranches: matchedBranches(kept),
    pusher: input.pusher,
    inventory: input.secretInventory,
  });
  return emit(report, flags.format);
}

async function runAudit(flags: Flags): Promise<number> {
  const token = flags.token ?? process.env.GITHUB_TOKEN;
  const org = flags.org;
  if (!org) throw new Error("audit requires --org <org>");
  let input: AuditInput;
  if (flags.events) {
    const raw = loadJson(flags.events) as
      | AuditEvent[]
      | { org: string; events: AuditEvent[] };
    input = Array.isArray(raw) ? { org, events: raw } : raw;
  } else {
    if (!token) {
      throw new Error(
        "audit live path requires an organization-owner token " +
          "(--token or GITHUB_TOKEN); otherwise pass --events <file>",
      );
    }
    input = await fetchAuditInput(org, token);
  }
  const { findings, preparedSecrets, actors } = evaluateAudit(input);
  const { kept, skipped } = applyAllowlist(findings, toAllowlist(flags));
  const report = buildReport({
    repo: org,
    path: "audit-log",
    findings: kept,
    skipped,
    matchedBranches: matchedBranches(kept),
    pusher: actors[0],
    preparedSecrets,
  });
  return emit(report, flags.format);
}

function runChecklist(flags: Flags): number {
  const target = flags.positional[0];
  if (!target) throw new Error("checklist requires <owner/repo>");
  if (!flags.report) throw new Error("checklist requires --report <file>");
  const report = loadJson(flags.report) as Report;
  if (report.repo !== target) {
    throw new Error(
      `report is for ${report.repo}, not ${target}; pass the matching report`,
    );
  }
  if (!report.rotateChecklist) {
    console.log(
      `No rotate checklist: verdict for ${target} is ${report.verdict}. ` +
        (report.nextCheck ?? ""),
    );
    return 0;
  }
  console.log(`Rotate checklist for ${target} (secret NAMES only):`);
  for (const item of report.rotateChecklist) {
    console.log(`  - ${item}`);
  }
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    return 0;
  }
  if (argv.includes("--version") || argv.includes("-V")) {
    console.log(VERSION);
    return 0;
  }
  try {
    const { command, flags } = parseArgs(argv);
    if (command === "scan") return await runScan(flags);
    if (command === "audit") return await runAudit(flags);
    if (command === "checklist") return runChecklist(flags);
    throw new Error(`unknown command "${command}" (see --help)`);
  } catch (err) {
    console.error(
      `gheist-guard: error: ${err instanceof Error ? err.message : String(err)}`,
    );
    return 2;
  }
}

const code = await main(process.argv.slice(2));
process.exit(code);
