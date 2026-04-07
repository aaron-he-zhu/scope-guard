#!/usr/bin/env node
/**
 * Scope Guard — PostToolUse hook entry point.
 *
 * Reads tool output as JSON from stdin, scans for sensitive content,
 * and optionally redacts it. Prints the filter result as JSON to stdout.
 *
 * Exit codes: 0 = clean, 1 = sensitive content detected
 *
 * Usage (Claude Code hooks):
 *   "command": "node dist/hook-post.js"
 */

import { readFileSync } from "node:fs";
import { OutputFilter } from "./output-filter.js";

function main(): void {
  let raw: string;
  try {
    raw = readFileSync(0, "utf-8");
  } catch {
    console.log(JSON.stringify({ filtered: false, error: "no input" }));
    process.exit(0);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Non-JSON output — scan raw text
    const filter = new OutputFilter();
    const result = filter.scan(raw);
    console.log(JSON.stringify(result));
    process.exit(result.filtered ? 1 : 0);
    return;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    console.log(JSON.stringify({ filtered: false }));
    process.exit(0);
    return;
  }

  const payload = parsed as Record<string, unknown>;
  const output = String(payload.tool_output ?? payload.output ?? payload.stdout ?? "");

  if (!output) {
    console.log(JSON.stringify({ filtered: false }));
    process.exit(0);
    return;
  }

  const filter = new OutputFilter();
  const redactEnabled = !!process.env.SCOPE_GUARD_REDACT_OUTPUT;

  if (redactEnabled) {
    const { text, result } = filter.redact(output);
    console.log(JSON.stringify({ ...result, redacted_output: text }));
    process.exit(result.filtered ? 1 : 0);
  } else {
    const result = filter.scan(output);
    console.log(JSON.stringify(result));
    process.exit(result.filtered ? 1 : 0);
  }
}

main();
