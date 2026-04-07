#!/usr/bin/env node
/**
 * scope-guard init — automated setup for Claude Code hooks.
 *
 * Creates .claude/settings.json with the Claude hooks and copies the bundled
 * SKILL.md into .claude/skills/scope-guard/.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PRE_HOOK_COMMAND =
  "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook.js\"";
const POST_HOOK_COMMAND =
  "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook-post.js\"";

type HookEntry = Record<string, unknown>;

function ensureHookCommand(
  entries: HookEntry[],
  expectedCommand: string,
  fileName: string,
): "added" | "updated" | "unchanged" {
  let matched = false;
  let updated = false;

  for (const entry of entries) {
    if (!Array.isArray(entry.hooks)) continue;
    for (const hook of entry.hooks as Record<string, unknown>[]) {
      if (typeof hook.command !== "string" || !hook.command.includes(fileName)) continue;
      matched = true;
      if (hook.command !== expectedCommand) {
        hook.command = expectedCommand;
        updated = true;
      }
    }
  }

  if (!matched) {
    entries.push({
      matcher: "",
      hooks: [{ type: "command", command: expectedCommand }],
    });
    return "added";
  }

  return updated ? "updated" : "unchanged";
}

function main(): void {
  const cwd = process.cwd();

  // 1. Set up hooks in .claude/settings.json
  const settingsPath = join(cwd, ".claude", "settings.json");

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
  const preToolUse = (hooks.PreToolUse ?? []) as HookEntry[];
  const postToolUse = (hooks.PostToolUse ?? []) as HookEntry[];

  const preAction = ensureHookCommand(preToolUse, PRE_HOOK_COMMAND, "hook.js");
  hooks.PreToolUse = preToolUse;
  console.log(
    preAction === "added"
      ? "[scope-guard] added PreToolUse hook"
      : preAction === "updated"
        ? "[scope-guard] updated PreToolUse hook"
        : "[scope-guard] PreToolUse hook already installed",
  );

  const postAction = ensureHookCommand(postToolUse, POST_HOOK_COMMAND, "hook-post.js");
  hooks.PostToolUse = postToolUse;
  console.log(
    postAction === "added"
      ? "[scope-guard] added PostToolUse hook"
      : postAction === "updated"
        ? "[scope-guard] updated PostToolUse hook"
        : "[scope-guard] PostToolUse hook already installed",
  );

  settings.hooks = hooks;
  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");

  // 2. Copy SKILL.md if available
  const skillDest = join(cwd, ".claude", "skills", "scope-guard", "SKILL.md");
  const skillSources = [join(PACKAGE_ROOT, "skills", "scope-guard", "SKILL.md")];

  if (!existsSync(skillDest)) {
    for (const src of skillSources) {
      if (existsSync(src)) {
        mkdirSync(dirname(skillDest), { recursive: true });
        copyFileSync(src, skillDest);
        console.log(`[scope-guard] copied SKILL.md to ${skillDest}`);
        break;
      }
    }
    if (!existsSync(skillDest)) {
      console.warn("[scope-guard] warning: bundled SKILL.md not found");
    }
  } else {
    console.log("[scope-guard] SKILL.md already installed");
  }

  console.log("\n[scope-guard] setup complete. Every tool call is now guarded.");
  console.log(`  hook: .claude/settings.json → PreToolUse → ${PRE_HOOK_COMMAND}`);
  console.log(`  post-hook: .claude/settings.json → PostToolUse → ${POST_HOOK_COMMAND}`);
  console.log("  skill: .claude/skills/scope-guard/SKILL.md");
  console.log("  audit: .claude/scope-guard-audit.jsonl (created on first tool call)");
}

main();
