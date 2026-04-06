/**
 * Lightweight audit log for scope-guard decisions.
 * TypeScript port of src/preflight/audit.py
 */

import { appendFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import type { CheckResult } from "./checker.js";

export interface AuditEntry {
  timestamp: string;
  tool: string;
  target: string;
  verdict: string;
  risk_level: string;
  scope_violation: boolean;
  reason: string;
}

export class AuditLog {
  constructor(readonly path: string) {}

  static default(): AuditLog {
    return new AuditLog(`${process.cwd()}/.claude/preflight-audit.jsonl`);
  }

  record(result: CheckResult): void {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      tool: result.tool,
      target: result.target,
      verdict: result.verdict,
      risk_level: result.risk_level,
      scope_violation: result.scope_violation,
      reason: result.reason,
    };
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
  }

  read(limit = 50): AuditEntry[] {
    if (!existsSync(this.path)) return [];
    const entries: AuditEntry[] = [];
    for (const line of readFileSync(this.path, "utf-8").trim().split("\n")) {
      if (!line) continue;
      try {
        entries.push(JSON.parse(line) as AuditEntry);
      } catch {
        continue; // skip malformed lines
      }
    }
    return entries.slice(-limit);
  }

  summary(): { total: number; verdicts?: Record<string, number>; scope_violations?: number } {
    const entries = this.read(9999);
    if (entries.length === 0) return { total: 0 };
    const verdicts: Record<string, number> = { allow: 0, warn: 0, block: 0 };
    let scopeViolations = 0;
    for (const e of entries) {
      verdicts[e.verdict] = (verdicts[e.verdict] ?? 0) + 1;
      if (e.scope_violation) scopeViolations++;
    }
    return { total: entries.length, verdicts, scope_violations: scopeViolations };
  }
}
