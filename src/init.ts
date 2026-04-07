#!/usr/bin/env node
/**
 * scope-guard init — automated setup for Claude Code hooks.
 *
 * Creates .claude/settings.json with the PreToolUse hook and copies
 * SKILL.md into .claude/skills/scope-guard/.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";

function main(): void {
  const cwd = process.cwd();

  // 1. Set up hook in .claude/settings.json
  const settingsPath = join(cwd, ".claude", "settings.json");
  const hookEntry = {
    matcher: "",
    hooks: [{ type: "command", command: "node dist/hook.js" }],
  };

  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    } catch {
      console.error(`[scope-guard] warning: could not parse ${settingsPath}, creating new`);
    }
  }

  // Merge hooks — don't overwrite existing hooks
  const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>;
  const preToolUse = (hooks.PreToolUse ?? []) as Record<string, unknown>[];

  // Check if scope-guard hook already exists
  const alreadyInstalled = preToolUse.some(
    (h) => Array.isArray(h.hooks) && h.hooks.some(
      (hh: Record<string, unknown>) => typeof hh.command === "string" && (hh.command as string).includes("hook.js"),
    ),
  );

  if (alreadyInstalled) {
    console.log("[scope-guard] hook already installed in .claude/settings.json");
  } else {
    preToolUse.push(hookEntry);
    hooks.PreToolUse = preToolUse;
    settings.hooks = hooks;
    mkdirSync(dirname(settingsPath), { recursive: true });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    console.log("[scope-guard] added PreToolUse hook to .claude/settings.json");
  }

  // 2. Copy SKILL.md if available
  const skillDest = join(cwd, ".claude", "skills", "scope-guard", "SKILL.md");
  const skillSources = [
    join(cwd, "skills", "scope-guard", "SKILL.md"),
    join(cwd, "SKILL.md"),
    join(dirname(new URL(import.meta.url).pathname), "..", "skills", "scope-guard", "SKILL.md"),
  ];

  if (!existsSync(skillDest)) {
    for (const src of skillSources) {
      if (existsSync(src)) {
        mkdirSync(dirname(skillDest), { recursive: true });
        copyFileSync(src, skillDest);
        console.log(`[scope-guard] copied SKILL.md to ${skillDest}`);
        break;
      }
    }
  } else {
    console.log("[scope-guard] SKILL.md already installed");
  }

  console.log("\n[scope-guard] setup complete. Every tool call is now guarded.");
  console.log("  hook: .claude/settings.json → PreToolUse → node dist/hook.js");
  console.log("  skill: .claude/skills/scope-guard/SKILL.md");
  console.log("  audit: .claude/scope-guard-audit.jsonl (created on first tool call)");
}

main();
