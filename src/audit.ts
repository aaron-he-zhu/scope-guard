/**
 * Audit log for scope-guard decisions with HMAC integrity signing and hash chain.
 *
 * Phase 3 enhancements:
 *   - Hash chain: each entry includes prev_hash linking to the previous entry
 *   - Session/user identity: session_id and user_id fields from env vars
 *   - HMAC key separation: SCOPE_GUARD_HMAC_KEY env var takes precedence over file-based key
 *   - verify() returns chain_breaks count for tamper detection
 *   - escalation_reason and content_flags preserved from CheckResult
 */

import { appendFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { createHmac, createHash, randomBytes } from "node:crypto";
import type { CheckResult } from "./checker.js";
import { ContentScanner } from "./content.js";

export interface AuditEntry {
  timestamp: string;
  tool: string;
  target: string;
  verdict: string;
  risk_level: string;
  scope_violation: boolean;
  reason: string;
  session_id?: string;
  user_id?: string;
  escalation_reason?: string;
  content_flags?: string[];
  matched_rules?: string[];
  // v3: MCP context
  mcp_server?: string;
  mcp_operation?: string;
  // v3: business context (resource ID stored as hash for PHI safety)
  resource_id_hash?: string;
  operation_scope?: "single" | "batch" | "export";
  transaction_amount?: string;
  prev_hash?: string;
  hmac?: string;
}

export interface VerifyResult {
  valid: number;
  tampered: number;
  unsigned: number;
  chain_breaks: number;
}

/** Resolve HMAC key: env var takes precedence, then file-based key. */
function getHmacKey(logPath: string): string {
  const envKey = process.env.SCOPE_GUARD_HMAC_KEY;
  if (envKey && envKey.length >= 16) return envKey;

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

/** Compute SHA-256 hash of a full signed entry (for chain linking). */
function entryHash(signedEntry: AuditEntry): string {
  return createHash("sha256").update(JSON.stringify(signedEntry)).digest("hex");
}

export class AuditLog {
  constructor(readonly path: string) {}

  static default(): AuditLog {
    return new AuditLog(`${process.cwd()}/.claude/scope-guard-audit.jsonl`);
  }

  record(result: CheckResult): void {
    const lastHash = this.lastEntryHash();

    const entry: Omit<AuditEntry, "hmac"> = {
      timestamp: new Date().toISOString(),
      tool: result.tool,
      target: result.target,
      verdict: result.verdict,
      risk_level: result.risk_level,
      scope_violation: result.scope_violation,
      reason: result.reason,
      ...(process.env.SCOPE_GUARD_SESSION_ID && { session_id: process.env.SCOPE_GUARD_SESSION_ID }),
      ...(process.env.SCOPE_GUARD_USER_ID && { user_id: process.env.SCOPE_GUARD_USER_ID }),
      ...(result.escalation_reason && { escalation_reason: result.escalation_reason }),
      ...(result.content_flags?.length && { content_flags: result.content_flags }),
      ...(result.matched_rules?.length && { matched_rules: result.matched_rules }),
      ...(result.params_summary?.mcp_server && { mcp_server: result.params_summary.mcp_server }),
      ...(result.params_summary?.mcp_operation && { mcp_operation: result.params_summary.mcp_operation }),
      ...(result.params_summary?.resource_id_hash && { resource_id_hash: result.params_summary.resource_id_hash }),
      ...(result.params_summary?.operation_scope && { operation_scope: result.params_summary.operation_scope }),
      ...(result.params_summary?.transaction_amount && { transaction_amount: result.params_summary.transaction_amount }),
      ...(lastHash && { prev_hash: lastHash }),
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

  /** Verify HMAC integrity and hash chain of all audit entries. */
  verify(): VerifyResult {
    const entries = this.read(50_000);
    const keyPath = this.path + ".key";
    const envKey = process.env.SCOPE_GUARD_HMAC_KEY;
    const hasKey = (envKey && envKey.length >= 16) || existsSync(keyPath);
    if (!hasKey) return { valid: 0, tampered: 0, unsigned: entries.length, chain_breaks: 0 };

    const key = getHmacKey(this.path);
    let valid = 0;
    let tampered = 0;
    let unsigned = 0;
    let chainBreaks = 0;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry.hmac) {
        unsigned++;
        continue;
      }
      const { hmac, ...rest } = entry;
      const expected = computeHmac(rest, key);
      if (hmac === expected) {
        valid++;
      } else {
        tampered++;
      }

      // Check hash chain
      if (i > 0 && entry.prev_hash) {
        const prevExpected = entryHash(entries[i - 1]);
        if (entry.prev_hash !== prevExpected) {
          chainBreaks++;
        }
      }
    }

    return { valid, tampered, unsigned, chain_breaks: chainBreaks };
  }

  summary(): { total: number; verdicts?: Record<string, number>; scope_violations?: number; escalations?: number } {
    const entries = this.read(50_000);
    if (entries.length === 0) return { total: 0 };
    const verdicts: Record<string, number> = { allow: 0, warn: 0, escalate: 0, block: 0 };
    let scopeViolations = 0;
    let escalations = 0;
    for (const e of entries) {
      verdicts[e.verdict] = (verdicts[e.verdict] ?? 0) + 1;
      if (e.scope_violation) scopeViolations++;
      if (e.verdict === "escalate") escalations++;
    }
    return { total: entries.length, verdicts, scope_violations: scopeViolations, escalations };
  }

  /**
   * Export audit entries with optional redaction.
   * Full log is signed as-is; redaction only applies to the exported output.
   * This preserves HMAC integrity while allowing safe sharing.
   */
  export(options?: { redact?: boolean; limit?: number }): string {
    const entries = this.read(options?.limit ?? 50_000);
    if (!options?.redact) {
      return entries.map(e => JSON.stringify(e)).join("\n");
    }
    const scanner = new ContentScanner();
    return entries.map(e => {
      const redacted = { ...e };
      if (redacted.target) {
        const scan = scanner.scan(redacted.target);
        if (scan.flags.length > 0) {
          let t = redacted.target;
          for (const flag of scan.flags) {
            const re = ContentScanner.getPattern(flag.pattern_name);
            if (re) t = t.replace(re, `[REDACTED:${flag.pattern_name}]`);
          }
          redacted.target = t;
        }
      }
      // Remove HMAC from redacted export (no longer verifiable after redaction)
      delete (redacted as Partial<AuditEntry>).hmac;
      return JSON.stringify(redacted);
    }).join("\n");
  }

  /** Get hash of the last entry in the log (for chain linking). */
  private lastEntryHash(): string | undefined {
    if (!existsSync(this.path)) return undefined;
    const content = readFileSync(this.path, "utf-8").trimEnd();
    if (!content) return undefined;
    const lines = content.split("\n");
    const lastLine = lines[lines.length - 1];
    if (!lastLine) return undefined;
    try {
      const entry = JSON.parse(lastLine) as AuditEntry;
      return entryHash(entry);
    } catch {
      return undefined;
    }
  }
}
