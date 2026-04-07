#!/usr/bin/env node
/**
 * Scope Guard — PostToolUse hook entry point.
 *
 * Reads tool output as JSON from stdin, scans for sensitive content,
 * and returns a Claude Code PostToolUse JSON decision.
 *
 * Usage (Claude Code hooks):
 *   "command": "node \"$CLAUDE_PROJECT_DIR/node_modules/scope-guard/dist/hook-post.js\""
 */

import { readFileSync } from "node:fs";
import { OutputFilter } from "./output-filter.js";

function formatPostToolDecision(
  output: string,
  redactEnabled: boolean,
): Record<string, unknown> {
  const filter = new OutputFilter();
  const { text, result } = redactEnabled
    ? filter.redact(output)
    : { text: output, result: filter.scan(output) };

  if (!result.filtered) {
    return {};
  }

  const additionalContext = redactEnabled
    ? [
        "Sensitive content was detected in the tool response.",
        "Use this redacted version instead of quoting the raw tool output:",
        text,
      ].join("\n\n")
    : `Sensitive content was detected in the tool response (${result.redacted_patterns.join(", ")}). Do not quote the raw output back to the user.`;

  return {
    decision: "block",
    reason: `Sensitive content detected in tool output (${result.redacted_patterns.join(", ")})`,
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext,
    },
  };
}

function main(): void {
  let raw: string;
  try {
    raw = readFileSync(0, "utf-8");
  } catch {
    console.log(JSON.stringify({}));
    process.exit(0);
    return;
  }

  const redactEnabled = !!process.env.SCOPE_GUARD_REDACT_OUTPUT;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.log(JSON.stringify(formatPostToolDecision(raw, redactEnabled)));
    process.exit(0);
    return;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    console.log(JSON.stringify({}));
    process.exit(0);
    return;
  }

  const payload = parsed as Record<string, unknown>;
  const rawOutput =
    payload.tool_response ??
    payload.tool_output ??
    payload.output ??
    payload.stdout ??
    "";
  const output =
    typeof rawOutput === "string" ? rawOutput : JSON.stringify(rawOutput);

  if (!output) {
    console.log(JSON.stringify({}));
    process.exit(0);
    return;
  }

  console.log(JSON.stringify(formatPostToolDecision(output, redactEnabled)));
  process.exit(0);
}

main();
