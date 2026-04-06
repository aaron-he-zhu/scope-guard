#!/usr/bin/env node
/**
 * Scope Guard — CLI hook entry point.
 *
 * Reads a tool call as JSON from stdin, runs the scope checker,
 * prints the verdict as JSON to stdout, and exits with:
 *   0 = allow, 1 = warn, 2 = block
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

const EXIT_CODES: Record<string, number> = { allow: 0, warn: 1, block: 2 };

function main(): void {
  let raw: string;
  try {
    raw = readFileSync(0, "utf-8"); // read stdin (fd 0)
  } catch {
    // No stdin — fail closed
    console.log(JSON.stringify({ verdict: "block", reason: "no input" }));
    process.exit(2);
    return; // unreachable, helps TS
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw);
  } catch {
    // Unparsable input — fail closed
    console.log(JSON.stringify({ verdict: "block", reason: "unparsable input" }));
    process.exit(2);
    return; // unreachable, helps TS
  }

  const toolName = (payload.tool_name ?? payload.tool ?? "") as string;
  const params = (payload.tool_input ?? payload.params ?? {}) as Record<string, unknown>;

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
  process.exit(EXIT_CODES[result.verdict] ?? 2);
}

main();
