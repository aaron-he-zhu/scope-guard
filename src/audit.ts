/**
 * Lightweight audit log for scope-guard decisions with HMAC integrity signing.
 */

import { appendFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { createHmac, randomBytes } from "node:crypto";
import type { CheckResult } from "./checker.js";

export interface AuditEntry {
  timestamp: string;
  tool: string;
  target: string;
  verdict: string;
  risk_level: string;
  scope_violation: boolean;
  reason: string;
  hmac?: string;
}

/** Generate or load an HMAC key for audit signing. */
function getHmacKey(logPath: string): string {
  const keyPath = logPath + ".key";
  if (existsSync(keyPath)) {
    return readFileSync(keyPath, "utf-8").trim();
  }
  const key = randomBytes(32).toString("hex");
  mkdirSync(dirname(keyPath), { recursive: true });
  appendFileSync(keyPath, key + "\n");
  return key;
}

/** Compute HMAC-SHA256 for an audit entry (excluding the hmac field). */
function computeHmac(entry: Omit<AuditEntry, "hmac">, key: string): string {
  const payload = JSON.stringify(entry);
  return createHmac("sha256", key).update(payload).digest("hex");
}

export class AuditLog {
  constructor(readonly path: string) {}

  static default(): AuditLog {
    return new AuditLog(`${process.cwd()}/.claude/scope-guard-audit.jsonl`);
  }

  record(result: CheckResult): void {
    const entry: Omit<AuditEntry, "hmac"> = {
      timestamp: new Date().toISOString(),
      tool: result.tool,
      target: result.target,
      verdict: result.verdict,
      risk_level: result.risk_level,
      scope_violation: result.scope_violation,
      reason: result.reason,
    };
    mkdirSync(dirname(this.path), { recursive: true });
    const key = getHmacKey(this.path);
    const signed: AuditEntry = { ...entry, hmac: computeHmac(entry, key) };
    appendFileSync(this.path, JSON.stringify(signed) + "\n");
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

  /** Verify HMAC integrity of all audit entries. */
  verify(): { valid: number; tampered: number; unsigned: number } {
    const entries = this.read(50_000);
    const keyPath = this.path + ".key";
    if (!existsSync(keyPath)) return { valid: 0, tampered: 0, unsigned: entries.length };
    const key = readFileSync(keyPath, "utf-8").trim();
    let valid = 0;
    let tampered = 0;
    let unsigned = 0;
    for (const entry of entries) {
      if (!entry.hmac) {
        unsigned++;
        continue;
      }
      const { hmac, ...rest } = entry;
      const expected = computeHmac(rest, key);
      if (hmac === expected) valid++;
      else tampered++;
    }
    return { valid, tampered, unsigned };
  }

  summary(): { total: number; verdicts?: Record<string, number>; scope_violations?: number } {
    const entries = this.read(50_000);
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
