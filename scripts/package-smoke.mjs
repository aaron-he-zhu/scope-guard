#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    input: options.input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function listCommands(settings, eventName) {
  const groups = Array.isArray(settings?.hooks?.[eventName]) ? settings.hooks[eventName] : [];
  const commands = [];

  for (const group of groups) {
    if (!Array.isArray(group?.hooks)) continue;
    for (const hook of group.hooks) {
      if (hook?.type === "command" && typeof hook.command === "string") {
        commands.push(hook.command);
      }
    }
  }

  return commands;
}

function runJson(command, args, options = {}) {
  return JSON.parse(run(command, args, options));
}

const tarballArg = process.argv[2];
assert.ok(tarballArg, "Usage: node scripts/package-smoke.mjs <tarball>");

const tarballPath = resolve(process.cwd(), tarballArg);
assert.ok(existsSync(tarballPath), `Tarball not found: ${tarballPath}`);

const packlist = run("tar", ["-tf", tarballPath]).split(/\r?\n/).filter(Boolean);
const packEntries = new Set(packlist);

for (const expected of [
  "package/package.json",
  "package/README.md",
  "package/.claude-plugin/plugin.json",
  "package/dist/hook.js",
  "package/dist/hook-post.js",
  "package/dist/init.js",
  "package/skills/scope-guard/SKILL.md",
]) {
  assert.ok(packEntries.has(expected), `Expected tarball entry missing: ${expected}`);
}

for (const unexpectedPrefix of [
  "package/.claude/",
  "package/.npm-cache/",
  "package/src/",
  "package/node_modules/",
]) {
  assert.ok(
    !packlist.some((entry) => entry.startsWith(unexpectedPrefix)),
    `Unexpected tarball entry found under ${unexpectedPrefix}`,
  );
}

const tmpRoot = mkdtempSync(join(tmpdir(), "scope-guard-package-smoke-"));

try {
  const npmCache = join(tmpRoot, ".npm-cache");
  const consumerRoot = join(tmpRoot, "consumer");
  const claudeDir = join(consumerRoot, ".claude");
  const subdir = join(consumerRoot, "subdir");
  const hookPath = join(consumerRoot, "node_modules", "scope-guard", "dist", "hook.js");
  const postHookPath = join(consumerRoot, "node_modules", "scope-guard", "dist", "hook-post.js");
  const env = { ...process.env, npm_config_cache: npmCache, CLAUDE_PROJECT_DIR: consumerRoot };

  mkdirSync(npmCache, { recursive: true });
  mkdirSync(consumerRoot, { recursive: true });
  writeFileSync(
    join(consumerRoot, "package.json"),
    JSON.stringify({ name: "scope-guard-consumer-smoke", private: true }, null, 2) + "\n",
  );

  run("npm", ["install", "--no-package-lock", tarballPath], { cwd: consumerRoot, env });

  for (const binName of [
    "scope-guard",
    "scope-guard-hook",
    "scope-guard-init",
    "scope-guard-cli",
    "scope-guard-post",
  ]) {
    assert.ok(
      existsSync(join(consumerRoot, "node_modules", ".bin", binName)),
      `Expected installed bin missing: ${binName}`,
    );
  }

  run("npx", ["--no-install", "scope-guard-init"], { cwd: consumerRoot, env });

  const settingsPath = join(claudeDir, "settings.json");
  assert.ok(existsSync(settingsPath), "scope-guard-init did not create .claude/settings.json");

  const settings = readJson(settingsPath);
  const preCommands = listCommands(settings, "PreToolUse");
  const postCommands = listCommands(settings, "PostToolUse");
  const expectedPre =
    "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook.js\"";
  const expectedPost =
    "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook-post.js\"";

  assert.ok(preCommands.includes(expectedPre), "PreToolUse hook command was not installed");
  assert.ok(postCommands.includes(expectedPost), "PostToolUse hook command was not installed");

  mkdirSync(join(consumerRoot, "src"), { recursive: true });
  mkdirSync(subdir, { recursive: true });
  writeFileSync(join(consumerRoot, "src", "app.ts"), "export const ready = true;\n");
  writeFileSync(
    join(claudeDir, "scope-boundary.json"),
    JSON.stringify({ files_in_scope: ["src/app.ts"] }, null, 2) + "\n",
  );

  const hookPayload = JSON.stringify({
    tool_name: "Read",
    tool_input: { file_path: "src/app.ts" },
  });

  assert.deepEqual(
    runJson("node", [hookPath], { cwd: consumerRoot, env, input: hookPayload }),
    {},
    "Root hook invocation should allow in-scope reads",
  );

  assert.deepEqual(
    runJson("node", [hookPath], { cwd: subdir, env, input: hookPayload }),
    {},
    "Hook should honor CLAUDE_PROJECT_DIR when launched from a subdirectory",
  );

  writeFileSync(join(claudeDir, "scope-guard-policy.json"), "{bad json\n");
  const malformedPolicyResult = runJson("node", [hookPath], {
    cwd: consumerRoot,
    env,
    input: hookPayload,
  });

  assert.equal(
    malformedPolicyResult?.hookSpecificOutput?.permissionDecision,
    "deny",
    "Malformed policy should fail closed with a deny decision",
  );
  assert.match(
    String(malformedPolicyResult?.hookSpecificOutput?.permissionDecisionReason ?? ""),
    /configuration error/i,
    "Malformed policy deny reason should explain the configuration error",
  );

  assert.deepEqual(
    runJson("node", [postHookPath], {
      cwd: consumerRoot,
      env,
      input: JSON.stringify({ tool_response: "all clear" }),
    }),
    {},
    "Clean post-tool output should pass through untouched",
  );

  const redactedPostResult = runJson("node", [postHookPath], {
    cwd: consumerRoot,
    env: { ...env, SCOPE_GUARD_REDACT_OUTPUT: "1" },
    input: JSON.stringify({ tool_response: "Patient SSN: 123-45-6789" }),
  });

  assert.equal(redactedPostResult?.decision, "block");
  assert.equal(redactedPostResult?.hookSpecificOutput?.hookEventName, "PostToolUse");
  assert.match(
    String(redactedPostResult?.hookSpecificOutput?.additionalContext ?? ""),
    /\[REDACTED:ssn\]/i,
    "Redacted PostToolUse output should contain the redacted payload",
  );
} finally {
  rmSync(tmpRoot, { recursive: true, force: true });
}

console.log("package smoke passed");
