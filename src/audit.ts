// Audit-log path for `audit --org <org>`.
// Live endpoint: GET /orgs/{org}/audit-log (organization owners only).
// The live audit-log end-to-end path is NOT testable without an
// organization-owner account, so v1 ships it fixture-verified only:
// pass --events <file> with recorded audit-log event payloads. The README
// states this limit plainly; the tool never claims a live audit result
// it did not run.

import type { AuditEvent, AuditInput } from "./types.js";

const API = "https://api.github.com";

export async function fetchAuditInput(
  org: string,
  token: string,
): Promise<AuditInput> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "gheist-guard",
    Authorization: `Bearer ${token}`,
  };
  const events: AuditEvent[] = [];
  // Phrases from the published audit runbooks. All four lifecycle
  // actions are queried: without the created phrase, the R4 triple
  // (created -> completed -> deleted) could never form from live data
  // and the audit path would be blind to its own headline rule. The
  // prepared phrase feeds the rotate checklist's secret-name inventory.
  // The API returns at most 100 events per page, so each phrase is
  // paged until an empty page, capped at 10 pages (1000 events) to
  // bound a single run. The cap is stated in the docs, not hidden.
  const phrases = [
    "action:workflows.created_workflow_run",
    "action:workflows.completed_workflow_run",
    "action:workflows.delete_workflow_run",
    "action:workflows.prepared_workflow_job",
  ];
  for (const phrase of phrases) {
    for (let page = 1; page <= 10; page++) {
      const res = await fetch(
        `${API}/orgs/${org}/audit-log?phrase=${encodeURIComponent(phrase)}&per_page=100&page=${page}`,
        { headers },
      );
      if (!res.ok) {
        throw new Error(`GitHub audit-log API ${res.status} for org ${org}`);
      }
      const rows = (await res.json()) as Record<string, unknown>[];
      if (rows.length === 0) break;
      for (const r of rows) {
        events.push({
          action: String(r.action ?? ""),
          runId: String(
            (r as { workflow_run_id?: unknown }).workflow_run_id ?? "",
          ),
          branch: (r as { workflow_run_branch?: unknown })
            .workflow_run_branch
            ? String(
                (r as { workflow_run_branch?: unknown })
                  .workflow_run_branch,
              )
            : undefined,
          actor: (r as { actor?: unknown }).actor
            ? String((r as { actor?: unknown }).actor)
            : undefined,
          userAgent: (r as { user_agent?: unknown }).user_agent
            ? String((r as { user_agent?: unknown }).user_agent)
            : undefined,
          timestamp: String(
            (r as { "@timestamp"?: unknown })["@timestamp"] ?? "",
          ),
          workflowPath: (r as { workflow_path?: unknown }).workflow_path
            ? String((r as { workflow_path?: unknown }).workflow_path)
            : undefined,
          // Defensive mapping only: the prepared-event secret field
          // name is NOT yet confirmed against a real organization
          // response (no org-owner account is available), so a row
          // without an array `secrets` field simply contributes no
          // names. Prepared-secret inventory stays fixture-verified
          // until an org owner confirms the live field. Never a
          // value: the model carries names only, by construction.
          secrets: Array.isArray(
            (r as { secrets?: unknown }).secrets,
          )
            ? ((r as { secrets?: unknown }).secrets as unknown[]).map(
                (s) => String(s),
              )
            : undefined,
        });
      }
    }
  }
  return { org, events };
}
