#!/usr/bin/env node
/**
 * Scope Guard v2 — CLI hook entry point.
 *
 * Reads a tool call as JSON from stdin, runs the scope checker,
 * prints the verdict as JSON to stdout, and exits with:
 *   0 = allow, 1 = warn, 2 = escalate, 3 = block
 *
 * Set SCOPE_GUARD_LEGACY_EXIT_CODES=1 to use v1 codes (0/1/2 without escalate).
 *
 * Usage (Claude Code hooks):
 *   "command": "node dist/hook.js"
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { RiskEngine } from "./risk.js";
import { ScopeBoundary } from "./scope.js";
import { AuditLog } from "./audit.js";

const LEGACY = !!process.env.SCOPE_GUARD_LEGACY_EXIT_CODES;

const EXIT_CODES: Record<string, number> = LEGACY
  ? { allow: 0, warn: 1, escalate: 2, block: 2 }
  : { allow: 0, warn: 1, escalate: 2, block: 3 };

function main(): void {
  let raw: string;
  try {
    raw = readFileSync(0, "utf-8"); // read stdin (fd 0)
  } catch {
    // No stdin — fail closed
    console.log(JSON.stringify({ verdict: "block", reason: "no input" }));
    process.exit(LEGACY ? 2 : 3);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.log(JSON.stringify({ verdict: "block", reason: "unparsable input" }));
    process.exit(LEGACY ? 2 : 3);
    return;
  }

  // Validate payload is a non-null object
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    console.log(JSON.stringify({ verdict: "block", reason: "payload must be a JSON object" }));
    process.exit(LEGACY ? 2 : 3);
    return;
  }

  const payload = parsed as Record<string, unknown>;
  const toolName = String(payload.tool_name ?? payload.tool ?? "");
  const params = (
    payload.tool_input !== null &&
    typeof payload.tool_input === "object" &&
    !Array.isArray(payload.tool_input)
      ? payload.tool_input
      : payload.params !== null &&
          typeof payload.params === "object" &&
          !Array.isArray(payload.params)
        ? payload.params
        : {}
  ) as Record<string, unknown>;

  const cwd = process.cwd();
  const scopePath = join(cwd, ".claude", "scope-boundary.json");
  const auditLogPath = join(cwd, ".claude", "scope-guard-audit.jsonl");

  const boundary = ScopeBoundary.load(scopePath);
  const engine = RiskEngine.default();
  const checker = new ScopeChecker(boundary, engine);
  const result = checker.check(toolName, params);

  // Write audit log
  try {
    const audit = new AuditLog(auditLogPath);
    audit.record(result);
  } catch (e) {
    console.error(`[scope-guard] audit write failed: ${e}`);
  }

  console.log(JSON.stringify(result));
  process.exit(EXIT_CODES[result.verdict] ?? (LEGACY ? 2 : 3));
}

main();
