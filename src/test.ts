/**
 * Scope Guard — test suite using Node built-in test runner.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

import { RiskLevel, RiskRule, RiskEngine, builtinRules, riskOrd } from "./risk.js";
import { ScopeBoundary, normalisePath } from "./scope.js";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { AuditLog } from "./audit.js";

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

describe("RiskRule", () => {
  it("matches tool and pattern", () => {
    const rule = new RiskRule({ name: "test", tool: "Bash", pattern: "rm -rf", risk: RiskLevel.HIGH });
    assert.equal(rule.matches("Bash", "rm -rf /tmp"), true);
    assert.equal(rule.matches("Edit", "rm -rf /tmp"), false);
  });

  it("wildcard tool matches any", () => {
    const rule = new RiskRule({ name: "test", tool: "*", pattern: "\\.env", risk: RiskLevel.HIGH });
    assert.equal(rule.matches("Edit", "file_path: .env"), true);
    assert.equal(rule.matches("Bash", "cat .env"), true);
  });

  it("case insensitive matching", () => {
    const rule = new RiskRule({ name: "test", tool: "Bash", pattern: "DROP TABLE", risk: RiskLevel.HIGH });
    assert.equal(rule.matches("Bash", "drop table users"), true);
    assert.equal(rule.matches("bash", "DROP TABLE users"), true);
  });

  it("rejects invalid regex", () => {
    assert.throws(() => new RiskRule({ name: "bad", tool: "*", pattern: "[invalid", risk: RiskLevel.HIGH }));
  });
});

describe("riskOrd", () => {
  it("orders levels correctly", () => {
    assert.ok(riskOrd(RiskLevel.LOW) < riskOrd(RiskLevel.MEDIUM));
    assert.ok(riskOrd(RiskLevel.MEDIUM) < riskOrd(RiskLevel.HIGH));
  });

  it("returns 0 for unknown values", () => {
    assert.equal(riskOrd("bogus" as RiskLevel), 0);
  });
});

describe("RiskEngine", () => {
  const engine = RiskEngine.default();

  // HIGH
  it("rm -rf is HIGH", () => assert.equal(engine.assess("Bash", { command: "rm -rf /tmp" }), RiskLevel.HIGH));
  it("git push --force is HIGH", () => assert.equal(engine.assess("Bash", { command: "git push --force" }), RiskLevel.HIGH));
  it("git push -f is HIGH", () => assert.equal(engine.assess("Bash", { command: "git push -f" }), RiskLevel.HIGH));
  it("git reset --hard is HIGH", () => assert.equal(engine.assess("Bash", { command: "git reset --hard" }), RiskLevel.HIGH));
  it("drop table is HIGH", () => assert.equal(engine.assess("Bash", { command: "drop table users" }), RiskLevel.HIGH));
  it(".env file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: ".env" }), RiskLevel.HIGH));
  it(".pem file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: "key.pem" }), RiskLevel.HIGH));
  it(".key file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: "server.key" }), RiskLevel.HIGH));
  it(".secret file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: "app.secret" }), RiskLevel.HIGH));
  it(".credentials file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: "db.credentials" }), RiskLevel.HIGH));
  it("curl POST is HIGH", () => assert.equal(engine.assess("Bash", { command: "curl -X POST http://a" }), RiskLevel.HIGH));
  it("npm publish is HIGH", () => assert.equal(engine.assess("Bash", { command: "npm publish" }), RiskLevel.HIGH));
  it("docker push is HIGH", () => assert.equal(engine.assess("Bash", { command: "docker push img" }), RiskLevel.HIGH));
  it("rmdir is HIGH", () => assert.equal(engine.assess("Bash", { command: "rmdir /tmp/foo" }), RiskLevel.HIGH));
  it("wget --post is HIGH", () => assert.equal(engine.assess("Bash", { command: "wget --post-data=x http://a" }), RiskLevel.HIGH));

  // MEDIUM
  it("Write tool is MEDIUM", () => assert.equal(engine.assess("Write", { file_path: "foo.ts" }), RiskLevel.MEDIUM));
  it("curl get is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "curl http://a" }), RiskLevel.MEDIUM));
  it("pip install is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "pip install x" }), RiskLevel.MEDIUM));
  it("npm install is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "npm install x" }), RiskLevel.MEDIUM));
  it("chmod is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "chmod 755 f" }), RiskLevel.MEDIUM));
  it("git checkout -- is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "git checkout -- ." }), RiskLevel.MEDIUM));

  // LOW
  it("ls is LOW", () => assert.equal(engine.assess("Bash", { command: "ls -la" }), RiskLevel.LOW));
  it("echo is LOW", () => assert.equal(engine.assess("Bash", { command: "echo hi" }), RiskLevel.LOW));
  it("Read tool is LOW", () => assert.equal(engine.assess("Read", { file_path: "f.ts" }), RiskLevel.LOW));
  it("empty command is LOW", () => assert.equal(engine.assess("Bash", { command: "" }), RiskLevel.LOW));

  // Sensitive file reads
  it("cat /etc/shadow is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "cat /etc/shadow" }), RiskLevel.MEDIUM));
  it("cat /etc/passwd is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "cat /etc/passwd" }), RiskLevel.MEDIUM));
  it("cat /etc/sudoers is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "cat /etc/sudoers" }), RiskLevel.MEDIUM));
  it("head .env is HIGH (secret_files rule)", () => assert.equal(engine.assess("Bash", { command: "head .env" }), RiskLevel.HIGH));
  it("cat safe file is LOW", () => assert.equal(engine.assess("Bash", { command: "cat README.md" }), RiskLevel.LOW));

  it("builtin rules count is 14", () => assert.equal(builtinRules().length, 14));

  it("matchingRules returns applicable rules", () => {
    const rules = engine.matchingRules("Bash", { command: "curl -X POST http://api" });
    assert.ok(rules.length >= 2); // matches curl_mutate AND network_read
    const names = rules.map((r) => r.name);
    assert.ok(names.includes("curl_mutate"));
    assert.ok(names.includes("network_read"));
  });

  it("matchingRules returns empty for safe commands", () => {
    const rules = engine.matchingRules("Bash", { command: "echo hi" });
    assert.equal(rules.length, 0);
  });
});

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

describe("ScopeBoundary", () => {
  it("empty scope", () => {
    const b = new ScopeBoundary();
    assert.equal(b.isEmpty, true);
  });

  it("file in scope exact", () => {
    const b = new ScopeBoundary({ files_in_scope: ["src/foo.ts"] });
    assert.equal(b.isFileInScope("src/foo.ts"), true);
    assert.equal(b.isFileInScope("src/bar.ts"), false);
  });

  it("file in scope via dir", () => {
    const b = new ScopeBoundary({ dirs_in_scope: ["src/"] });
    assert.equal(b.isFileInScope("src/foo.ts"), true);
    assert.equal(b.isFileInScope("lib/foo.ts"), false);
  });

  it("path traversal blocked", () => {
    const b = new ScopeBoundary({ dirs_in_scope: ["src/auth/"] });
    assert.equal(b.isFileInScope("src/auth/../../etc/passwd"), false);
  });

  it("absolute path matches relative scope", () => {
    const b = new ScopeBoundary({ dirs_in_scope: ["src/auth/"] });
    assert.equal(b.isFileInScope("/src/auth/login.ts"), true);
  });

  it("normalise collapses ./", () => {
    assert.equal(normalisePath("./src/foo.ts"), normalisePath("src/foo.ts"));
  });

  it("normalise blocks traversal beyond root", () => {
    assert.equal(normalisePath("../../etc/passwd"), "__blocked__");
  });

  it("normalise blocks backslash traversal", () => {
    assert.equal(normalisePath("src\\..\\..\\etc\\passwd"), "__blocked__");
  });

  it("normalise converts backslashes to forward slashes", () => {
    const b = new ScopeBoundary({ dirs_in_scope: ["src/auth/"] });
    assert.equal(b.isFileInScope("src\\auth\\login.ts"), true);
  });

  it("expand scope", () => {
    const b = new ScopeBoundary({ files_in_scope: ["a.ts"] });
    b.expandScope(["b.ts"], undefined, "test");
    assert.equal(b.files_in_scope.length, 2);
    assert.equal(b.revisions.length, 1);
  });

  it("risk_level validates enum values", () => {
    const valid = new ScopeBoundary({ risk_level: "high" });
    assert.equal(valid.risk_level, RiskLevel.HIGH);

    const invalid = new ScopeBoundary({ risk_level: "critical" });
    assert.equal(invalid.risk_level, RiskLevel.LOW); // defaults to LOW
  });

  it("save/load roundtrip", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-"));
    const p = join(tmp, "scope.json");
    const b = new ScopeBoundary({ files_in_scope: ["a.ts"], task_summary: "test" });
    b.save(p);
    const loaded = ScopeBoundary.load(p);
    assert.deepEqual(loaded.files_in_scope, ["a.ts"]);
    assert.equal(loaded.task_summary, "test");
    rmSync(tmp, { recursive: true });
  });

  it("load missing returns empty", () => {
    const b = ScopeBoundary.load("/nonexistent/path.json");
    assert.equal(b.isEmpty, true);
  });
});

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

describe("ScopeChecker", () => {
  const boundary = new ScopeBoundary({
    files_in_scope: ["src/auth/login.ts"],
    dirs_in_scope: ["src/auth/"],
  });
  const checker = new ScopeChecker(boundary);

  // Read-only tools
  it("Read is always ALLOW", () => {
    assert.equal(checker.check("Read", { file_path: "/etc/passwd" }).verdict, CheckVerdict.ALLOW);
  });

  it("Glob is always ALLOW", () => {
    assert.equal(checker.check("Glob", {}).verdict, CheckVerdict.ALLOW);
  });

  it("Grep is always ALLOW", () => {
    assert.equal(checker.check("Grep", { pattern: "foo" }).verdict, CheckVerdict.ALLOW);
  });

  it("WebSearch is always ALLOW", () => {
    assert.equal(checker.check("WebSearch", { query: "test" }).verdict, CheckVerdict.ALLOW);
  });

  it("WebFetch is always ALLOW", () => {
    assert.equal(checker.check("WebFetch", { url: "http://x" }).verdict, CheckVerdict.ALLOW);
  });

  it("TodoWrite is always ALLOW", () => {
    assert.equal(checker.check("TodoWrite", {}).verdict, CheckVerdict.ALLOW);
  });

  it("AskUserQuestion is always ALLOW", () => {
    assert.equal(checker.check("AskUserQuestion", {}).verdict, CheckVerdict.ALLOW);
  });

  // File-path tools: in scope
  it("Edit in scope = ALLOW", () => {
    assert.equal(checker.check("Edit", { file_path: "src/auth/login.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("Edit in scope dir = ALLOW", () => {
    assert.equal(checker.check("Edit", { file_path: "src/auth/utils.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("NotebookEdit in scope = ALLOW", () => {
    assert.equal(checker.check("NotebookEdit", { notebook_path: "src/auth/nb.ipynb" }).verdict, CheckVerdict.ALLOW);
  });

  // File-path tools: out of scope
  it("Edit out of scope = WARN", () => {
    const r = checker.check("Edit", { file_path: "src/api/routes.ts" });
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.equal(r.scope_violation, true);
  });

  it("Edit .env out of scope = BLOCK", () => {
    assert.equal(checker.check("Edit", { file_path: ".env" }).verdict, CheckVerdict.BLOCK);
  });

  // Bash
  it("Bash low risk = ALLOW", () => {
    assert.equal(checker.check("Bash", { command: "ls" }).verdict, CheckVerdict.ALLOW);
  });

  it("Bash medium risk = WARN", () => {
    assert.equal(checker.check("Bash", { command: "curl http://x" }).verdict, CheckVerdict.WARN);
  });

  it("Bash high risk = BLOCK", () => {
    assert.equal(checker.check("Bash", { command: "rm -rf /" }).verdict, CheckVerdict.BLOCK);
  });

  // Edge cases
  it("Write with no file_path = WARN", () => {
    assert.equal(checker.check("Write", {}).verdict, CheckVerdict.WARN);
  });

  it("uses default RiskEngine when none provided", () => {
    const c = new ScopeChecker(new ScopeBoundary());
    assert.equal(c.check("Bash", { command: "rm -rf /" }).verdict, CheckVerdict.BLOCK);
  });

  it("unknown tool falls back to risk-only", () => {
    const c = new ScopeChecker(new ScopeBoundary());
    const r = c.check("SomeNewTool", { file_path: "foo.ts" });
    assert.equal(r.verdict, CheckVerdict.ALLOW);
    assert.equal(r.scope_violation, false);
  });

  it("empty tool name returns WARN", () => {
    const r = checker.check("", {});
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.equal(r.reason, "empty or missing tool name");
  });
});

describe("ScopeChecker empty scope", () => {
  const checker = new ScopeChecker(new ScopeBoundary());

  it("Edit follows risk only", () => {
    assert.equal(checker.check("Edit", { file_path: "any.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("Edit .env still blocks", () => {
    assert.equal(checker.check("Edit", { file_path: ".env" }).verdict, CheckVerdict.BLOCK);
  });

  it("rm -rf still blocks", () => {
    assert.equal(checker.check("Bash", { command: "rm -rf /" }).verdict, CheckVerdict.BLOCK);
  });
});

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

describe("AuditLog", () => {
  it("record and read", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);

    log.record({
      verdict: CheckVerdict.ALLOW,
      tool: "Read",
      target: "f.ts",
      reason: "read-only",
      risk_level: RiskLevel.LOW,
      scope_violation: false,
    });

    const entries = log.read();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].tool, "Read");
    assert.equal(entries[0].verdict, "allow");

    rmSync(tmp, { recursive: true });
  });

  it("summary counts", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);

    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    log.record({ verdict: CheckVerdict.WARN, tool: "Bash", target: "", reason: "", risk_level: RiskLevel.MEDIUM, scope_violation: false });
    log.record({ verdict: CheckVerdict.BLOCK, tool: "Bash", target: "", reason: "", risk_level: RiskLevel.HIGH, scope_violation: true });

    const s = log.summary();
    assert.equal(s.total, 3);
    assert.equal(s.verdicts?.allow, 1);
    assert.equal(s.verdicts?.warn, 1);
    assert.equal(s.verdicts?.block, 1);
    assert.equal(s.scope_violations, 1);

    rmSync(tmp, { recursive: true });
  });

  it("read skips malformed JSON lines", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    writeFileSync(p, '{"tool":"Read","verdict":"allow"}\nNOT_JSON\n{"tool":"Edit","verdict":"warn"}\n');
    const log = new AuditLog(p);
    const entries = log.read();
    assert.equal(entries.length, 2);
    assert.equal(entries[0].tool, "Read");
    assert.equal(entries[1].tool, "Edit");
    rmSync(tmp, { recursive: true });
  });

  it("read returns empty for missing file", () => {
    const log = new AuditLog("/nonexistent/audit.jsonl");
    assert.deepEqual(log.read(), []);
  });

  it("default() creates with standard path", () => {
    const log = AuditLog.default();
    assert.ok(log.path.endsWith(".claude/scope-guard-audit.jsonl"));
  });
});

// ---------------------------------------------------------------------------
// Hook (integration — subprocess)
// ---------------------------------------------------------------------------

describe("hook.ts integration", () => {
  const hookPath = join(import.meta.dirname, "..", "dist", "hook.js");

  function runHook(input: string): { stdout: string; exitCode: number } {
    try {
      const stdout = execFileSync("node", [hookPath], {
        input,
        encoding: "utf-8",
        timeout: 5000,
        env: { ...process.env, HOME: tmpdir() },
        cwd: mkdtempSync(join(tmpdir(), "sg-hook-")),
      });
      return { stdout: stdout.trim(), exitCode: 0 };
    } catch (e: unknown) {
      const err = e as { stdout?: string; status?: number };
      return { stdout: (err.stdout ?? "").trim(), exitCode: err.status ?? 2 };
    }
  }

  it("allow on Read tool", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool_name: "Read", tool_input: { file_path: "f.ts" } }));
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "allow");
  });

  it("block on rm -rf", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /" } }));
    assert.equal(exitCode, 2);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "block");
  });

  it("warn on curl", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl http://x" } }));
    assert.equal(exitCode, 1);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "warn");
  });

  it("block on empty stdin", () => {
    const { stdout, exitCode } = runHook("");
    assert.equal(exitCode, 2);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "block");
  });

  it("block on malformed JSON", () => {
    const { stdout, exitCode } = runHook("{not json}");
    assert.equal(exitCode, 2);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "block");
  });

  it("block on null payload", () => {
    const { stdout, exitCode } = runHook("null");
    assert.equal(exitCode, 2);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "block");
  });

  it("block on array payload", () => {
    const { stdout, exitCode } = runHook("[]");
    assert.equal(exitCode, 2);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "block");
  });

  it("accepts tool/params field names", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool: "Read", params: { file_path: "f.ts" } }));
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "allow");
  });

  it("warn on empty tool name", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool_name: "", tool_input: {} }));
    assert.equal(exitCode, 1);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "warn");
  });

  it("warn on cat /etc/shadow", () => {
    const { stdout, exitCode } = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "cat /etc/shadow" } }));
    assert.equal(exitCode, 1);
    const result = JSON.parse(stdout);
    assert.equal(result.verdict, "warn");
  });
});

// ---------------------------------------------------------------------------
// Index (OpenClaw plugin — unit test via mock)
// ---------------------------------------------------------------------------

describe("index.ts plugin", () => {
  it("exports a valid plugin entry", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;
    assert.equal(plugin.id, "scope-guard");
    assert.equal(plugin.name, "Scope Guard");
    assert.equal(typeof plugin.register, "function");
  });

  it("registers a before_tool_call hook", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;
    let registeredEvent = "";
    let registeredOptions: Record<string, unknown> = {};

    const mockApi = {
      registerHook(event: string, _handler: unknown, options?: Record<string, unknown>) {
        registeredEvent = event;
        registeredOptions = options ?? {};
      },
      getConfig: () => ({}),
      getWorkspacePath: () => tmpdir(),
    };

    plugin.register(mockApi as never);
    assert.equal(registeredEvent, "before_tool_call");
    assert.equal(registeredOptions.name, "scope-guard.check");
  });

  it("hook allows Read tool", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;
    let handler: (event: Record<string, unknown>) => Promise<Record<string, unknown>> = async () => ({});

    const tmp = mkdtempSync(join(tmpdir(), "sg-plugin-"));
    const mockApi = {
      registerHook(_event: string, h: typeof handler) { handler = h; },
      getConfig: () => ({}),
      getWorkspacePath: () => tmp,
    };

    plugin.register(mockApi as never);
    const result = await handler({ toolName: "Read", toolCallId: "1", params: { file_path: "f.ts" } });
    assert.equal(result.block, undefined);
    assert.equal(result.requireApproval, undefined);
    rmSync(tmp, { recursive: true });
  });

  it("hook blocks rm -rf", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;
    let handler: (event: Record<string, unknown>) => Promise<Record<string, unknown>> = async () => ({});

    const tmp = mkdtempSync(join(tmpdir(), "sg-plugin-"));
    const mockApi = {
      registerHook(_event: string, h: typeof handler) { handler = h; },
      getConfig: () => ({}),
      getWorkspacePath: () => tmp,
    };

    plugin.register(mockApi as never);
    const result = await handler({ toolName: "Bash", toolCallId: "2", params: { command: "rm -rf /" } });
    assert.equal(result.block, true);
    assert.ok((result.blockReason as string).includes("BLOCKED"));
    rmSync(tmp, { recursive: true });
  });

  it("hook fails closed on internal error", async () => {
    const mod = await import("./index.js");
    const plugin = mod.default;
    let handler: (event: Record<string, unknown>) => Promise<Record<string, unknown>> = async () => ({});

    const mockApi = {
      registerHook(_event: string, h: typeof handler) { handler = h; },
      getConfig: () => { throw new Error("config error"); },
      getWorkspacePath: () => tmpdir(),
    };

    plugin.register(mockApi as never);
    const result = await handler({ toolName: "Read", toolCallId: "3", params: {} });
    assert.equal(result.block, true);
    assert.ok((result.blockReason as string).includes("fail closed"));
  });
});

// ---------------------------------------------------------------------------
// Mutation resilience & boundary tests
// ---------------------------------------------------------------------------

describe("mutation resilience", () => {
  const boundary = new ScopeBoundary({
    files_in_scope: ["src/auth/login.ts"],
    dirs_in_scope: ["src/auth/"],
  });
  const checker = new ScopeChecker(boundary);

  // Verdict boundaries — flipping > to >= or < to <= should fail these
  it("MEDIUM risk is WARN not ALLOW", () => {
    const r = checker.check("Bash", { command: "curl http://x" });
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.notEqual(r.verdict, CheckVerdict.ALLOW);
  });

  it("HIGH risk is BLOCK not WARN", () => {
    const r = checker.check("Bash", { command: "rm -rf /" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.notEqual(r.verdict, CheckVerdict.WARN);
  });

  it("LOW risk is ALLOW not WARN", () => {
    const r = checker.check("Bash", { command: "ls" });
    assert.equal(r.verdict, CheckVerdict.ALLOW);
    assert.notEqual(r.verdict, CheckVerdict.WARN);
  });

  // Out-of-scope: low risk must WARN (not ALLOW)
  it("out-of-scope low-risk Edit is WARN not ALLOW", () => {
    const r = checker.check("Edit", { file_path: "src/api/routes.ts" });
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.equal(r.scope_violation, true);
  });

  // Out-of-scope: high risk must BLOCK (not WARN)
  it("out-of-scope high-risk Edit is BLOCK not WARN", () => {
    const r = checker.check("Edit", { file_path: ".env" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.notEqual(r.verdict, CheckVerdict.WARN);
  });

  // riskOrd must strictly increase — detects flipped comparisons
  it("riskOrd LOW < MEDIUM < HIGH strictly", () => {
    assert.ok(riskOrd(RiskLevel.LOW) < riskOrd(RiskLevel.MEDIUM));
    assert.ok(riskOrd(RiskLevel.MEDIUM) < riskOrd(RiskLevel.HIGH));
    assert.ok(riskOrd(RiskLevel.LOW) < riskOrd(RiskLevel.HIGH));
    // Not equal
    assert.notEqual(riskOrd(RiskLevel.LOW), riskOrd(RiskLevel.MEDIUM));
    assert.notEqual(riskOrd(RiskLevel.MEDIUM), riskOrd(RiskLevel.HIGH));
  });

  // Read-only must not be WARN or BLOCK
  it("Read tool is strictly ALLOW", () => {
    const r = checker.check("Read", { file_path: "/etc/shadow" });
    assert.equal(r.verdict, CheckVerdict.ALLOW);
    assert.equal(r.risk_level, RiskLevel.LOW);
  });
});

describe("command truncation", () => {
  it("truncates at 500 chars in Bash check", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const longCmd = "x".repeat(1000);
    const r = checker.check("Bash", { command: longCmd });
    assert.equal(r.target.length, 500);
  });

  it("truncates at 500 chars in extractTarget", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const longUrl = "http://" + "x".repeat(1000);
    const r = checker.check("SomeNewTool", { url: longUrl });
    assert.equal(r.target.length, 500);
  });

  it("short commands are not truncated", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const r = checker.check("Bash", { command: "echo hello" });
    assert.equal(r.target, "echo hello");
  });
});
