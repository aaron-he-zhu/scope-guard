#!/usr/bin/env node
/**
 * Scope Guard v2 — CLI hook entry point.
 *
 * Reads a tool call as JSON from stdin, runs the scope checker,
 * and returns a Claude Code PreToolUse JSON decision.
 *
 * Usage (Claude Code hooks):
 *   "command": "node \"$CLAUDE_PROJECT_DIR/node_modules/scope-guard/dist/hook.js\""
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { AuditLog } from "./audit.js";
import { loadEnforcementRuntime } from "./runtime.js";
import { RiskLevel } from "./risk.js";

const LEGACY = !!process.env.SCOPE_GUARD_LEGACY_EXIT_CODES;

const EXIT_CODES: Record<string, number> = LEGACY
  ? { allow: 0, warn: 1, escalate: 2, block: 2 }
  : { allow: 0, warn: 0, escalate: 0, block: 0 };

function formatClaudeDecision(result: {
  verdict: string;
  reason: string;
  escalation_reason?: string;
}): Record<string, unknown> {
  if (result.verdict === CheckVerdict.ALLOW) {
    return {};
  }

  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision:
        result.verdict === CheckVerdict.BLOCK ? "deny" : "ask",
      permissionDecisionReason: result.escalation_reason ?? result.reason,
    },
  };
}

function emitHookResult(result: {
  verdict: CheckVerdict;
  tool: string;
  target: string;
  reason: string;
  risk_level: RiskLevel;
  scope_violation: boolean;
  escalation_reason?: string;
}): never {
  console.log(JSON.stringify(LEGACY ? result : formatClaudeDecision(result)));
  process.exit(EXIT_CODES[result.verdict] ?? 0);
}

function failClosed(toolName: string, reason: string): never {
  emitHookResult({
    verdict: CheckVerdict.BLOCK,
    tool: toolName,
    target: "",
    reason,
    risk_level: RiskLevel.HIGH,
    scope_violation: true,
  });
}

function main(): void {
  let raw: string;
  try {
    raw = readFileSync(0, "utf-8"); // read stdin (fd 0)
  } catch {
    failClosed("", "scope-guard did not receive hook input");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    failClosed("", "scope-guard received malformed hook input");
  }

  // Validate payload is a non-null object
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    failClosed("", "scope-guard expected a JSON object hook payload");
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

  let result;
  try {
    const workspacePath = resolve(process.env.CLAUDE_PROJECT_DIR || process.cwd());
    const runtime = loadEnforcementRuntime(workspacePath);
    const checker = runtime.checker;
    result = checker.check(toolName, params);

    // Write audit log
    try {
      const audit = new AuditLog(runtime.auditLogPath);
      audit.record(result);
    } catch (e) {
      console.error(`[scope-guard] audit write failed: ${e}`);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    console.error(`[scope-guard] internal error: ${message}`);
    failClosed(toolName, `scope-guard configuration error: ${message}`);
  }

  emitHookResult(result);
}

main();
