/**
 * Scope Guard — test suite using Node built-in test runner.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

import { RiskLevel, RiskRule, RiskEngine, builtinRules, riskOrd } from "./risk.js";
import { ScopeBoundary, normalisePath } from "./scope.js";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { AuditLog } from "./audit.js";
import { ContentScanner } from "./content.js";
import { loadPolicy, buildRiskEngine, validatePolicy, type PolicyConfig } from "./policy.js";
import { OutputFilter } from "./output-filter.js";

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

  it("builtin rules count is 38", () => assert.equal(builtinRules().length, 38));

  // v2 SQL mutation rules
  it("INSERT INTO is HIGH", () => assert.equal(engine.assess("Bash", { command: "INSERT INTO users VALUES (1)" }), RiskLevel.HIGH));
  it("UPDATE SET is HIGH", () => assert.equal(engine.assess("Bash", { command: "UPDATE users SET name='x'" }), RiskLevel.HIGH));
  it("DELETE FROM is HIGH", () => assert.equal(engine.assess("Bash", { command: "DELETE FROM users WHERE id=1" }), RiskLevel.HIGH));
  it("ALTER TABLE is HIGH", () => assert.equal(engine.assess("Bash", { command: "ALTER TABLE users ADD col int" }), RiskLevel.HIGH));
  it("MERGE INTO is HIGH", () => assert.equal(engine.assess("Bash", { command: "MERGE INTO t USING s ON ..." }), RiskLevel.HIGH));
  it("CREATE OR REPLACE is HIGH", () => assert.equal(engine.assess("Bash", { command: "CREATE OR REPLACE TABLE t AS SELECT 1" }), RiskLevel.HIGH));
  it("COPY INTO is HIGH", () => assert.equal(engine.assess("Bash", { command: "COPY INTO @stage FROM t" }), RiskLevel.HIGH));

  // v2 messaging rules
  it("send_message is MEDIUM", () => assert.equal(engine.assess("mcp__slack__send_message", { text: "hi" }), RiskLevel.MEDIUM));
  it("broadcast is HIGH", () => assert.equal(engine.assess("mcp__slack__broadcast", { text: "hi" }), RiskLevel.HIGH));
  it("publish is HIGH", () => assert.equal(engine.assess("mcp__hubspot__publish", { id: "1" }), RiskLevel.HIGH));

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
    assert.equal(b.load_state, "missing");
  });

  it("load array config is invalid", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-boundary-"));
    const p = join(tmp, "scope.json");
    writeFileSync(p, "[]\n");
    const b = ScopeBoundary.load(p);
    assert.equal(b.load_state, "invalid");
    assert.ok(b.load_error?.includes("JSON object"));
    rmSync(tmp, { recursive: true });
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
  it("Read in-scope file is ALLOW", () => {
    assert.equal(checker.check("Read", { file_path: "src/auth/login.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("Read sensitive out-of-scope file is WARN", () => {
    assert.equal(checker.check("Read", { file_path: "/etc/passwd" }).verdict, CheckVerdict.WARN);
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

  it("WebFetch blocked URL is BLOCK", () => {
    const urlChecker = new ScopeChecker(
      new ScopeBoundary({ resources: { blocked_urls: ["https://example.com/private*"] } }),
    );
    const result = urlChecker.check("WebFetch", { url: "https://example.com/private-doc" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
    assert.equal(result.scope_violation, true);
  });

  it("WebFetch URL allowlist mismatch is BLOCK", () => {
    const urlChecker = new ScopeChecker(
      new ScopeBoundary({ resources: { allowed_urls: ["https://docs.example.com/*"] } }),
    );
    const result = urlChecker.check("WebFetch", { url: "https://example.com/secret" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
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

  it("unknown tool is WARN for safety", () => {
    const c = new ScopeChecker(new ScopeBoundary());
    const r = c.check("SomeNewTool", { file_path: "foo.ts" });
    assert.equal(r.verdict, CheckVerdict.WARN);
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

describe("ScopeChecker loaded boundary state", () => {
  it("missing boundary fails closed", () => {
    const checker = new ScopeChecker(
      new ScopeBoundary(undefined, { load_state: "missing" }),
    );
    const result = checker.check("Edit", { file_path: "src/outside.ts" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
    assert.equal(result.scope_violation, true);
  });

  it("invalid boundary fails closed", () => {
    const checker = new ScopeChecker(
      new ScopeBoundary(undefined, { load_state: "invalid" }),
    );
    const result = checker.check("Bash", { command: "ls" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
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

  it("record includes HMAC signature", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "f.ts", reason: "ok", risk_level: RiskLevel.LOW, scope_violation: false });
    const entries = log.read();
    assert.equal(entries.length, 1);
    assert.ok(entries[0].hmac, "entry should have hmac field");
    assert.equal(typeof entries[0].hmac, "string");
    assert.equal(entries[0].hmac!.length, 64); // SHA-256 hex
    rmSync(tmp, { recursive: true });
  });

  it("verify passes for untampered entries", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    log.record({ verdict: CheckVerdict.BLOCK, tool: "Bash", target: "rm", reason: "", risk_level: RiskLevel.HIGH, scope_violation: false });
    const result = log.verify();
    assert.equal(result.valid, 2);
    assert.equal(result.tampered, 0);
    assert.equal(result.unsigned, 0);
    assert.equal(result.chain_breaks, 0);
    rmSync(tmp, { recursive: true });
  });

  it("verify detects tampered entries", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    // Tamper with the file
    const content = readFileSync(p, "utf-8");
    writeFileSync(p, content.replace('"allow"', '"block"'));
    const result = log.verify();
    assert.equal(result.tampered, 1);
    assert.equal(result.valid, 0);
    rmSync(tmp, { recursive: true });
  });

  it("verify fails when key is missing for signed entries", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    rmSync(p + ".key");
    const result = log.verify();
    assert.equal(result.valid, 0);
    assert.equal(result.tampered, 1);
    rmSync(tmp, { recursive: true });
  });

  it("verify counts malformed lines as tampering", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    writeFileSync(p, readFileSync(p, "utf-8") + "NOT_JSON\n");
    const result = log.verify();
    assert.ok(result.tampered >= 1);
    assert.ok(result.chain_breaks >= 1);
    rmSync(tmp, { recursive: true });
  });

  it("record refuses to append after malformed tail", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    writeFileSync(p, readFileSync(p, "utf-8") + "NOT_JSON\n");
    assert.throws(() => {
      log.record({ verdict: CheckVerdict.WARN, tool: "Bash", target: "", reason: "", risk_level: RiskLevel.MEDIUM, scope_violation: false });
    }, /malformed/);
    rmSync(tmp, { recursive: true });
  });

  it("hash chain links entries", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    log.record({ verdict: CheckVerdict.WARN, tool: "Bash", target: "", reason: "", risk_level: RiskLevel.MEDIUM, scope_violation: false });
    log.record({ verdict: CheckVerdict.BLOCK, tool: "Bash", target: "", reason: "", risk_level: RiskLevel.HIGH, scope_violation: false });
    const entries = log.read();
    assert.equal(entries.length, 3);
    assert.equal(entries[0].prev_hash, undefined); // first entry has no prev
    assert.ok(entries[1].prev_hash, "second entry should have prev_hash");
    assert.ok(entries[2].prev_hash, "third entry should have prev_hash");
    assert.notEqual(entries[1].prev_hash, entries[2].prev_hash);
    const result = log.verify();
    assert.equal(result.chain_breaks, 0);
    rmSync(tmp, { recursive: true });
  });

  it("session_id and user_id from env", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    const origSession = process.env.SCOPE_GUARD_SESSION_ID;
    const origUser = process.env.SCOPE_GUARD_USER_ID;
    process.env.SCOPE_GUARD_SESSION_ID = "test-session-123";
    process.env.SCOPE_GUARD_USER_ID = "user@example.com";
    try {
      log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
      const entries = log.read();
      assert.equal(entries[0].session_id, "test-session-123");
      assert.equal(entries[0].user_id, "user@example.com");
    } finally {
      if (origSession === undefined) delete process.env.SCOPE_GUARD_SESSION_ID;
      else process.env.SCOPE_GUARD_SESSION_ID = origSession;
      if (origUser === undefined) delete process.env.SCOPE_GUARD_USER_ID;
      else process.env.SCOPE_GUARD_USER_ID = origUser;
    }
    rmSync(tmp, { recursive: true });
  });

  it("HMAC key from env var takes precedence", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    const origKey = process.env.SCOPE_GUARD_HMAC_KEY;
    process.env.SCOPE_GUARD_HMAC_KEY = "a]".repeat(16); // 32 chars, valid
    try {
      log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
      const result = log.verify();
      assert.equal(result.valid, 1);
      assert.equal(result.tampered, 0);
    } finally {
      if (origKey === undefined) delete process.env.SCOPE_GUARD_HMAC_KEY;
      else process.env.SCOPE_GUARD_HMAC_KEY = origKey;
    }
    rmSync(tmp, { recursive: true });
  });

  it("escalation_reason and content_flags in audit entry", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({
      verdict: CheckVerdict.ESCALATE,
      tool: "Read",
      target: "lawsuit.md",
      reason: "escalation keyword",
      risk_level: RiskLevel.HIGH,
      scope_violation: false,
      escalation_reason: "Contains lawsuit keyword",
      content_flags: ["ssn", "credit_card"],
      matched_rules: ["messaging_broadcast"],
    });
    const entries = log.read();
    assert.equal(entries[0].escalation_reason, "Contains lawsuit keyword");
    assert.deepEqual(entries[0].content_flags, ["ssn", "credit_card"]);
    assert.deepEqual(entries[0].matched_rules, ["messaging_broadcast"]);
    rmSync(tmp, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// Hook (integration — subprocess)
// ---------------------------------------------------------------------------

describe("hook.ts integration", () => {
  const hookPath = join(import.meta.dirname, "..", "dist", "hook.js");

  function runHook(
    input: string,
    scopeConfig?: Record<string, unknown>,
  ): { stdout: string; exitCode: number } {
    const cwd = mkdtempSync(join(tmpdir(), "sg-hook-"));
    if (scopeConfig) {
      const claudeDir = join(cwd, ".claude");
      mkdirSync(claudeDir, { recursive: true });
      writeFileSync(join(claudeDir, "scope-boundary.json"), JSON.stringify(scopeConfig));
    }
    try {
      const stdout = execFileSync("node", [hookPath], {
        input,
        encoding: "utf-8",
        timeout: 5000,
        env: { ...process.env, HOME: tmpdir() },
        cwd,
      });
      return { stdout: stdout.trim(), exitCode: 0 };
    } catch (e: unknown) {
      const err = e as { stdout?: string; status?: number };
      return { stdout: (err.stdout ?? "").trim(), exitCode: err.status ?? 2 };
    }
  }

  it("allow on in-scope Read tool", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Read", tool_input: { file_path: "f.ts" } }),
      { files_in_scope: ["f.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.deepEqual(result, {});
  });

  it("block on rm -rf", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /" } }),
      { files_in_scope: ["src/app.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("warn on curl", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl http://x" } }),
      { files_in_scope: ["src/app.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  });

  it("block on empty stdin", () => {
    const { stdout, exitCode } = runHook("");
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("block on malformed JSON", () => {
    const { stdout, exitCode } = runHook("{not json}");
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("block on null payload", () => {
    const { stdout, exitCode } = runHook("null");
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("block on array payload", () => {
    const { stdout, exitCode } = runHook("[]");
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("accepts tool/params field names", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool: "Read", params: { file_path: "f.ts" } }),
      { files_in_scope: ["f.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.deepEqual(result, {});
  });

  it("warn on empty tool name", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "", tool_input: {} }),
      { files_in_scope: ["src/app.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  });

  it("warn on cat /etc/shadow", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Bash", tool_input: { command: "cat /etc/shadow" } }),
      { files_in_scope: ["src/app.ts"] },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  });

  it("escalate maps to ask decision", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Read", tool_input: { file_path: "lawsuit-doc.md" } }),
      { files_in_scope: ["lawsuit-doc.md"], resources: { escalation_keywords: ["lawsuit"] } },
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  });

  it("missing boundary denies tool use", () => {
    const { stdout, exitCode } = runHook(
      JSON.stringify({ tool_name: "Read", tool_input: { file_path: "f.ts" } }),
    );
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });

  it("uses CLAUDE_PROJECT_DIR as hook workspace root", () => {
    const root = mkdtempSync(join(tmpdir(), "sg-hook-root-"));
    const subdir = join(root, "nested");
    mkdirSync(join(root, ".claude"), { recursive: true });
    mkdirSync(subdir, { recursive: true });
    writeFileSync(join(root, ".claude", "scope-boundary.json"), JSON.stringify({
      files_in_scope: ["f.ts"],
    }));
    const stdout = execFileSync("node", [hookPath], {
      input: JSON.stringify({ tool_name: "Read", tool_input: { file_path: "f.ts" } }),
      encoding: "utf-8",
      timeout: 5000,
      env: {
        ...process.env,
        HOME: tmpdir(),
        CLAUDE_PROJECT_DIR: root,
      },
      cwd: subdir,
    });
    assert.deepEqual(JSON.parse(stdout.trim()), {});
    rmSync(root, { recursive: true });
  });

  it("malformed policy denies with structured output", () => {
    const cwd = mkdtempSync(join(tmpdir(), "sg-hook-policy-"));
    const claudeDir = join(cwd, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(join(claudeDir, "scope-boundary.json"), JSON.stringify({
      files_in_scope: ["f.ts"],
    }));
    writeFileSync(join(claudeDir, "scope-guard-policy.json"), "{bad json\n");
    const stdout = execFileSync("node", [hookPath], {
      input: JSON.stringify({ tool_name: "Read", tool_input: { file_path: "f.ts" } }),
      encoding: "utf-8",
      timeout: 5000,
      env: { ...process.env, HOME: tmpdir() },
      cwd,
    });
    const result = JSON.parse(stdout.trim());
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
    assert.ok(String(result.hookSpecificOutput.permissionDecisionReason).includes("configuration error"));
    rmSync(cwd, { recursive: true });
  });
});

describe("hook-post.ts integration", () => {
  const hookPath = join(import.meta.dirname, "..", "dist", "hook-post.js");

  function runHookPost(
    input: string,
    env?: Record<string, string>,
  ): { stdout: string; exitCode: number } {
    try {
      const stdout = execFileSync("node", [hookPath], {
        input,
        encoding: "utf-8",
        timeout: 5000,
        env: { ...process.env, ...env },
      });
      return { stdout: stdout.trim(), exitCode: 0 };
    } catch (e: unknown) {
      const err = e as { stdout?: string; status?: number };
      return { stdout: (err.stdout ?? "").trim(), exitCode: err.status ?? 2 };
    }
  }

  it("returns empty JSON for clean output", () => {
    const { stdout, exitCode } = runHookPost(JSON.stringify({ tool_response: "hello" }));
    assert.equal(exitCode, 0);
    assert.deepEqual(JSON.parse(stdout), {});
  });

  it("blocks on sensitive tool_response", () => {
    const { stdout, exitCode } = runHookPost(JSON.stringify({ tool_response: "SSN: 123-45-6789" }));
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.decision, "block");
    assert.ok(String(result.reason).includes("Sensitive content"));
  });

  it("redacts raw text output when enabled", () => {
    const { stdout, exitCode } = runHookPost("SSN: 123-45-6789", {
      SCOPE_GUARD_REDACT_OUTPUT: "1",
    });
    assert.equal(exitCode, 0);
    const result = JSON.parse(stdout);
    assert.equal(result.decision, "block");
    assert.ok(String(result.hookSpecificOutput.additionalContext).includes("[REDACTED:ssn]"));
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
    const claudeDir = join(tmp, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(join(claudeDir, "scope-boundary.json"), JSON.stringify({
      files_in_scope: ["f.ts"],
    }));
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

  it("hook blocks when boundary is missing", async () => {
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
    const result = await handler({ toolName: "Read", toolCallId: "missing", params: { file_path: "f.ts" } });
    assert.equal(result.block, true);
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

  // Sensitive reads must not silently allow
  it("Read of sensitive file is WARN not ALLOW", () => {
    const r = checker.check("Read", { file_path: "/etc/shadow" });
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.equal(r.risk_level, RiskLevel.MEDIUM);
  });
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

describe("init.ts", () => {
  it("creates settings.json with hook", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-init-"));
    execFileSync("node", [join(import.meta.dirname, "..", "dist", "init.js")], {
      cwd: tmp,
      encoding: "utf-8",
      timeout: 5000,
    });
    const settingsPath = join(tmp, ".claude", "settings.json");
    assert.ok(existsSync(settingsPath), "settings.json should exist");
    const settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    assert.ok(settings.hooks?.PreToolUse?.length >= 1);
    const hookCmd = settings.hooks.PreToolUse[0].hooks[0].command;
    assert.ok(hookCmd.includes("node_modules/scope-guard/dist/hook.js"));
    rmSync(tmp, { recursive: true });
  });

  it("is idempotent — running twice doesn't duplicate hook", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-init-"));
    const run = () => execFileSync("node", [join(import.meta.dirname, "..", "dist", "init.js")], {
      cwd: tmp,
      encoding: "utf-8",
      timeout: 5000,
    });
    run();
    run();
    const settings = JSON.parse(readFileSync(join(tmp, ".claude", "settings.json"), "utf-8"));
    assert.equal(settings.hooks.PreToolUse.length, 1, "hook should not be duplicated");
    rmSync(tmp, { recursive: true });
  });

  it("merges with existing settings", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-init-"));
    const claudeDir = join(tmp, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(join(claudeDir, "settings.json"), JSON.stringify({ permissions: { allow: ["Read"] } }, null, 2));
    execFileSync("node", [join(import.meta.dirname, "..", "dist", "init.js")], {
      cwd: tmp,
      encoding: "utf-8",
      timeout: 5000,
    });
    const settings = JSON.parse(readFileSync(join(claudeDir, "settings.json"), "utf-8"));
    assert.deepEqual(settings.permissions, { allow: ["Read"] }, "existing settings preserved");
    assert.ok(settings.hooks?.PreToolUse?.length >= 1, "hook added");
    rmSync(tmp, { recursive: true });
  });

  it("updates legacy hook commands in place", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-init-"));
    const claudeDir = join(tmp, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(join(claudeDir, "settings.json"), JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "", hooks: [{ type: "command", command: "node dist/hook.js" }] }],
        PostToolUse: [{ matcher: "", hooks: [{ type: "command", command: "node dist/hook-post.js" }] }],
      },
    }, null, 2));
    execFileSync("node", [join(import.meta.dirname, "..", "dist", "init.js")], {
      cwd: tmp,
      encoding: "utf-8",
      timeout: 5000,
    });
    const settings = JSON.parse(readFileSync(join(claudeDir, "settings.json"), "utf-8"));
    assert.equal(settings.hooks.PreToolUse.length, 1);
    assert.equal(settings.hooks.PostToolUse.length, 1);
    assert.equal(
      settings.hooks.PreToolUse[0].hooks[0].command,
      "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook.js\"",
    );
    assert.equal(
      settings.hooks.PostToolUse[0].hooks[0].command,
      "node \"${CLAUDE_PROJECT_DIR:-$PWD}/node_modules/scope-guard/dist/hook-post.js\"",
    );
    rmSync(tmp, { recursive: true });
  });

  it("copies the bundled skill instead of a consumer-local SKILL.md", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-init-"));
    writeFileSync(join(tmp, "SKILL.md"), "local skill that should not be copied\n");
    execFileSync("node", [join(import.meta.dirname, "..", "dist", "init.js")], {
      cwd: tmp,
      encoding: "utf-8",
      timeout: 5000,
    });
    const installedSkill = readFileSync(
      join(tmp, ".claude", "skills", "scope-guard", "SKILL.md"),
      "utf-8",
    );
    const bundledSkill = readFileSync(
      join(import.meta.dirname, "..", "skills", "scope-guard", "SKILL.md"),
      "utf-8",
    );
    assert.equal(installedSkill, bundledSkill);
    rmSync(tmp, { recursive: true });
  });
});

describe("command truncation", () => {
  it("truncates at 500 chars in Bash check", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const longCmd = "x".repeat(1000);
    const r = checker.check("Bash", { command: longCmd });
    assert.equal(r.target.length, 500);
  });

  it("truncates at 500 chars in extractTarget via MCP", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const longUrl = "http://" + "x".repeat(1000);
    const r = checker.check("mcp__test__get_data", { url: longUrl });
    assert.equal(r.target.length, 500);
  });

  it("short commands are not truncated", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const r = checker.check("Bash", { command: "echo hello" });
    assert.equal(r.target, "echo hello");
  });
});

// ---------------------------------------------------------------------------
// v2: MCP tool classification
// ---------------------------------------------------------------------------

describe("MCP tool classification", () => {
  const checker = new ScopeChecker(new ScopeBoundary());

  it("MCP write tool is WARN (generic write)", () => {
    const r = checker.check("mcp__hubspot__update_contact", { contact_id: "123" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("MCP deal mutation is BLOCK (crm_deal_mutation rule)", () => {
    const r = checker.check("mcp__hubspot__update_deal", { deal_id: "123" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("MCP read tool is ALLOW", () => {
    const r = checker.check("mcp__hubspot__get_deal", { deal_id: "123" });
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });

  it("MCP delete is WARN", () => {
    const r = checker.check("mcp__jira__delete_issue", { issue_id: "X-1" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("MCP send_message is WARN (messaging_single rule makes MEDIUM)", () => {
    const r = checker.check("mcp__slack__send_message", { text: "hi" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("MCP broadcast is BLOCK (messaging_broadcast + write verb)", () => {
    const r = checker.check("mcp__slack__broadcast", { text: "hi" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("MCP publish is BLOCK (publish_schedule HIGH)", () => {
    const r = checker.check("mcp__hubspot__publish", { post_id: "1" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("MCP schedule is WARN (write verb, no matching rule for MEDIUM+)", () => {
    const r = checker.check("mcp__calendar__schedule", { event: "test" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("MCP start_run is WARN (write verb)", () => {
    const r = checker.check("mcp__benchling__start_run", { protocol: "p1" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("MCP with SQL mutation in params is BLOCK", () => {
    const r = checker.check("mcp__snowflake__execute", { sql: "DELETE FROM users WHERE 1=1" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("MCP with secret in params is BLOCK", () => {
    const r = checker.check("mcp__hubspot__get_contacts", { file_path: ".env" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("MCP mixed allowed and blocked resources is BLOCK", () => {
    const boundary = new ScopeBoundary({
      resources: {
        allowed_resources: ["hubspot:contacts:*"],
        blocked_resources: ["hubspot:deals:*"],
      },
    });
    const mixedChecker = new ScopeChecker(boundary);
    const r = mixedChecker.check("mcp__hubspot__update_record", {
      contact_id: "123",
      deal_id: "456",
    });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.equal(r.scope_violation, true);
  });
});

describe("MCP org boundary", () => {
  it("allowed server passes", () => {
    const b = new ScopeBoundary({ org_boundary: { allowed_mcp_servers: ["hubspot", "jira"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__hubspot__get_deal", {});
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });

  it("blocked server is BLOCK", () => {
    const b = new ScopeBoundary({ org_boundary: { blocked_mcp_servers: ["slack"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__slack__send_message", { text: "hi" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.equal(r.scope_violation, true);
  });

  it("server not in allowed list is BLOCK", () => {
    const b = new ScopeBoundary({ org_boundary: { allowed_mcp_servers: ["hubspot"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__slack__get_messages", {});
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });

  it("no org boundary means all servers allowed", () => {
    const b = new ScopeBoundary();
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__anything__get_data", {});
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });
});

describe("Resource scoping", () => {
  it("allowed resource passes", () => {
    const b = new ScopeBoundary({ resources: { allowed_resources: ["snowflake:analytics:*"] } });
    assert.equal(b.isResourceAllowed("snowflake:analytics:events"), "allowed");
  });

  it("blocked resource is blocked", () => {
    const b = new ScopeBoundary({ resources: { blocked_resources: ["snowflake:production:*"] } });
    assert.equal(b.isResourceAllowed("snowflake:production:users"), "blocked");
  });

  it("protected resource is protected", () => {
    const b = new ScopeBoundary({ resources: { protected_resources: ["*:gl_*"] } });
    assert.equal(b.isResourceAllowed("snowflake:gl_journal_entries"), "protected");
  });

  it("resource not in allowed list is blocked", () => {
    const b = new ScopeBoundary({ resources: { allowed_resources: ["hubspot:deals:*"] } });
    assert.equal(b.isResourceAllowed("hubspot:contacts:list"), "blocked");
  });

  it("no resource config means all allowed", () => {
    const b = new ScopeBoundary();
    assert.equal(b.isResourceAllowed("anything:here"), "allowed");
  });

  it("glob ** matches remaining", () => {
    const b = new ScopeBoundary({ resources: { allowed_resources: ["snowflake:**"] } });
    assert.equal(b.isResourceAllowed("snowflake:analytics:events"), "allowed");
  });
});

describe("Escalation keywords", () => {
  it("escalation keyword in Read target triggers ESCALATE", () => {
    const b = new ScopeBoundary({ resources: { escalation_keywords: ["lawsuit", "chargeback"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("Read", { file_path: "docs/lawsuit-response.md" });
    assert.equal(r.verdict, CheckVerdict.ESCALATE);
    assert.ok(r.escalation_reason);
  });

  it("escalation keyword in MCP params triggers ESCALATE", () => {
    const b = new ScopeBoundary({ resources: { escalation_keywords: ["lawsuit"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__intercom__get_conversation", { query: "customer lawsuit threat" });
    assert.equal(r.verdict, CheckVerdict.ESCALATE);
  });

  it("blocked keyword in MCP params triggers WARN", () => {
    const b = new ScopeBoundary({ resources: { blocked_keywords: ["confidential"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__notion__search", { query: "confidential roadmap" });
    assert.equal(r.verdict, CheckVerdict.WARN);
  });

  it("no keywords = no escalation", () => {
    const b = new ScopeBoundary();
    const checker = new ScopeChecker(b);
    const r = checker.check("Read", { file_path: "normal-file.ts" });
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });
});

describe("Protected resources on Read", () => {
  it("Read of protected resource is BLOCK", () => {
    const b = new ScopeBoundary({ resources: { protected_resources: ["*privileged*"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("Read", { file_path: "docs/privileged-memo.pdf" });
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.equal(r.scope_violation, true);
  });
});

describe("expandScope gate", () => {
  it("expand_requires_reason blocks empty reason", () => {
    const b = new ScopeBoundary({ files_in_scope: ["a.ts"], expand_requires_reason: true });
    assert.throws(() => b.expandScope(["b.ts"], undefined, ""), /non-empty reason/);
  });

  it("expand_requires_reason allows with reason", () => {
    const b = new ScopeBoundary({ files_in_scope: ["a.ts"], expand_requires_reason: true });
    b.expandScope(["b.ts"], undefined, "user requested");
    assert.equal(b.files_in_scope.length, 2);
  });
});

// ---------------------------------------------------------------------------
// v2: Content Scanner
// ---------------------------------------------------------------------------

describe("ContentScanner", () => {
  const scanner = new ContentScanner();

  it("detects SSN pattern", () => {
    const r = scanner.scan("SSN is 123-45-6789");
    assert.ok(r.flags.some(f => f.pattern_name === "ssn"));
    assert.equal(r.highest_risk, RiskLevel.HIGH);
  });

  it("detects credit card", () => {
    const r = scanner.scan("card: 4111 1111 1111 1111");
    assert.ok(r.flags.some(f => f.pattern_name === "credit_card"));
  });

  it("detects MRN", () => {
    const r = scanner.scan("MRN: 123456");
    assert.ok(r.flags.some(f => f.pattern_name === "mrn"));
  });

  it("detects API key assignment", () => {
    const r = scanner.scan("api_key=sk_live_abc123def456");
    assert.ok(r.flags.some(f => f.pattern_name === "api_key_assign"));
  });

  it("detects bearer token", () => {
    const r = scanner.scan("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test");
    assert.ok(r.flags.some(f => f.pattern_name === "bearer_token"));
  });

  it("detects large base64 blob", () => {
    const r = scanner.scan("data: " + "A".repeat(250));
    assert.ok(r.flags.some(f => f.pattern_name === "base64_large"));
  });

  it("normal code returns no flags", () => {
    const r = scanner.scan("const x = 42; function foo() { return x; }");
    assert.equal(r.flags.length, 0);
    assert.equal(r.highest_risk, RiskLevel.LOW);
  });

  it("empty string returns no flags", () => {
    const r = scanner.scan("");
    assert.equal(r.flags.length, 0);
  });
});

// ---------------------------------------------------------------------------
// v2: 4-verdict model
// ---------------------------------------------------------------------------

describe("4-verdict model", () => {
  it("ESCALATE is a valid verdict", () => {
    assert.equal(CheckVerdict.ESCALATE, "escalate");
  });
});

// ---------------------------------------------------------------------------
// v2: Policy engine
// ---------------------------------------------------------------------------

describe("PolicyConfig", () => {
  it("loadPolicy returns empty for missing file", () => {
    const config = loadPolicy("/nonexistent/policy.json");
    assert.deepEqual(config, {});
  });

  it("loadPolicy loads a basic policy", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-policy-"));
    const p = join(tmp, "policy.json");
    const policy: PolicyConfig = {
      compliance_mode: "hipaa",
      blocked_tools: ["WebFetch"],
    };
    writeFileSync(p, JSON.stringify(policy));
    const loaded = loadPolicy(p);
    assert.equal(loaded.compliance_mode, "hipaa");
    assert.ok(loaded.blocked_tools?.includes("WebFetch"));
    // HIPAA preset adds extra rules
    assert.ok(loaded.extra_rules && loaded.extra_rules.length > 0);
    assert.equal(loaded.require_scope_boundary, true);
    rmSync(tmp, { recursive: true });
  });

  it("extends chain merges policies", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-policy-"));
    const basePath = join(tmp, "base.json");
    const childPath = join(tmp, "child.json");
    writeFileSync(basePath, JSON.stringify({
      tool_overrides: { Write: "medium" },
      blocked_tools: ["WebFetch"],
    }));
    writeFileSync(childPath, JSON.stringify({
      extends: "base.json",
      tool_overrides: { Write: "high" },
      blocked_tools: ["Bash"],
    }));
    const loaded = loadPolicy(childPath);
    // Most restrictive wins for tool_overrides
    assert.equal(loaded.tool_overrides?.Write, "high");
    // Union for blocked_tools
    assert.ok(loaded.blocked_tools?.includes("WebFetch"));
    assert.ok(loaded.blocked_tools?.includes("Bash"));
    rmSync(tmp, { recursive: true });
  });

  it("extends depth limit throws", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-policy-"));
    // Create a chain of 7 files, each extending the next
    for (let i = 0; i < 7; i++) {
      const p = join(tmp, `p${i}.json`);
      writeFileSync(p, JSON.stringify({ extends: `p${i + 1}.json` }));
    }
    writeFileSync(join(tmp, "p7.json"), JSON.stringify({}));
    assert.throws(() => loadPolicy(join(tmp, "p0.json")), /max depth/);
    rmSync(tmp, { recursive: true });
  });

  it("buildRiskEngine includes extra rules", () => {
    const engine = buildRiskEngine({
      extra_rules: [
        { name: "custom_test", tool: "Bash", pattern: "my_dangerous_cmd", risk: RiskLevel.HIGH },
      ],
    });
    assert.equal(engine.assess("Bash", { command: "my_dangerous_cmd" }), RiskLevel.HIGH);
  });

  it("buildRiskEngine applies tool_overrides as a risk floor", () => {
    const engine = buildRiskEngine({
      tool_overrides: { Read: RiskLevel.HIGH },
    });
    assert.equal(engine.assess("Read", { file_path: "notes.txt" }), RiskLevel.HIGH);
  });

  it("extends + compliance_mode still applies the compliance preset", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-policy-"));
    const basePath = join(tmp, "base.json");
    const childPath = join(tmp, "child.json");
    writeFileSync(basePath, JSON.stringify({ blocked_tools: ["Bash"] }));
    writeFileSync(childPath, JSON.stringify({
      extends: "base.json",
      compliance_mode: "hipaa",
    }));
    const loaded = loadPolicy(childPath);
    assert.ok(loaded.blocked_tools?.includes("Bash"));
    assert.equal(loaded.require_scope_boundary, true);
    assert.ok(loaded.extra_rules && loaded.extra_rules.length > 0);
    rmSync(tmp, { recursive: true });
  });

  it("most-restrictive-wins for max_risk_auto_allow", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-policy-"));
    const basePath = join(tmp, "base.json");
    const childPath = join(tmp, "child.json");
    writeFileSync(basePath, JSON.stringify({ max_risk_auto_allow: "medium" }));
    writeFileSync(childPath, JSON.stringify({ extends: "base.json", max_risk_auto_allow: "low" }));
    const loaded = loadPolicy(childPath);
    assert.equal(loaded.max_risk_auto_allow, "low");
    rmSync(tmp, { recursive: true });
  });
});

describe("validatePolicy", () => {
  it("valid policy passes", () => {
    const result = validatePolicy({
      compliance_mode: "hipaa",
      extra_rules: [{ name: "test", tool: "*", pattern: "foo", risk: RiskLevel.HIGH }],
    });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it("invalid compliance_mode is error", () => {
    const result = validatePolicy({ compliance_mode: "bogus" as any });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes("compliance_mode")));
  });

  it("invalid regex in extra_rules is error", () => {
    const result = validatePolicy({
      extra_rules: [{ name: "bad", tool: "*", pattern: "[invalid", risk: RiskLevel.HIGH }],
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes("invalid regex")));
  });

  it("invalid risk level is error", () => {
    const result = validatePolicy({
      tool_overrides: { Bash: "extreme" as any },
    });
    assert.equal(result.valid, false);
  });
});

describe("policy enforcement", () => {
  it("blocked_tools are enforced by ScopeChecker", () => {
    const checker = new ScopeChecker(
      new ScopeBoundary({ files_in_scope: ["src/app.ts"] }),
      undefined,
      undefined,
      { blocked_tools: ["Bash"] },
    );
    const result = checker.check("Bash", { command: "echo ok" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
  });

  it("require_scope_boundary blocks empty loaded boundaries", () => {
    const checker = new ScopeChecker(
      new ScopeBoundary({}),
      undefined,
      undefined,
      { require_scope_boundary: true },
    );
    const result = checker.check("Read", { file_path: "notes.txt" });
    assert.equal(result.verdict, CheckVerdict.BLOCK);
  });

  it("max_risk_auto_allow can allow medium-risk reads", () => {
    const checker = new ScopeChecker(
      new ScopeBoundary({ files_in_scope: ["/etc/passwd"] }),
      undefined,
      undefined,
      { max_risk_auto_allow: RiskLevel.MEDIUM },
    );
    const result = checker.check("Read", { file_path: "/etc/passwd" });
    assert.equal(result.verdict, CheckVerdict.ALLOW);
  });
});

describe("package metadata", () => {
  it("maps the primary scope-guard bin to the CLI entrypoint", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf-8"));
    assert.equal(pkg.bin["scope-guard"], "./dist/cli.js");
    assert.equal(pkg.bin["scope-guard-hook"], "./dist/hook.js");
  });

  it("points package metadata at the scope-guard repository", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf-8"));
    const plugin = JSON.parse(readFileSync(join(import.meta.dirname, "..", ".claude-plugin", "plugin.json"), "utf-8"));
    assert.equal(pkg.repository.url, "https://github.com/aaron-he-zhu/scope-guard.git");
    assert.equal(pkg.homepage, "https://github.com/aaron-he-zhu/scope-guard");
    assert.equal(pkg.bugs.url, "https://github.com/aaron-he-zhu/scope-guard/issues");
    assert.equal(plugin.repository, "https://github.com/aaron-he-zhu/scope-guard");
    assert.equal(plugin.homepage, "https://github.com/aaron-he-zhu/scope-guard");
  });
});

// ---------------------------------------------------------------------------
// v2: Output filter
// ---------------------------------------------------------------------------

describe("OutputFilter", () => {
  const filter = new OutputFilter();

  it("clean output is not filtered", () => {
    const r = filter.scan("Hello, world!");
    assert.equal(r.filtered, false);
    assert.equal(r.redacted_patterns.length, 0);
    assert.equal(r.risk_level, RiskLevel.LOW);
  });

  it("SSN in output is detected", () => {
    const r = filter.scan("Patient SSN: 123-45-6789");
    assert.equal(r.filtered, true);
    assert.ok(r.redacted_patterns.includes("ssn"));
    assert.equal(r.risk_level, RiskLevel.HIGH);
  });

  it("redact replaces SSN", () => {
    const { text, result } = filter.redact("Patient SSN: 123-45-6789");
    assert.ok(text.includes("[REDACTED:ssn]"));
    assert.ok(!text.includes("123-45-6789"));
    assert.equal(result.filtered, true);
  });

  it("redact preserves clean text", () => {
    const { text, result } = filter.redact("const x = 42;");
    assert.equal(text, "const x = 42;");
    assert.equal(result.filtered, false);
  });

  it("multiple patterns detected", () => {
    const { text, result } = filter.redact("SSN: 123-45-6789, API key: api_key=sk_live_verylongkeymaterial");
    assert.ok(result.redacted_patterns.includes("ssn"));
    assert.ok(result.redacted_patterns.includes("api_key_assign"));
    assert.ok(text.includes("[REDACTED:ssn]"));
  });

  it("bearer token redacted", () => {
    const { text } = filter.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig");
    assert.ok(text.includes("[REDACTED:bearer_token]"));
  });
});

// ---------------------------------------------------------------------------
// v3: Escalation keyword word-boundary matching
// ---------------------------------------------------------------------------

describe("v3 keyword boundary matching", () => {
  it("lawsuit matches standalone", () => {
    const b = new ScopeBoundary({ resources: { escalation_keywords: ["lawsuit"] } });
    assert.deepEqual(b.matchEscalationKeywords("filed a lawsuit today"), ["lawsuit"]);
  });

  it("lawsuit does NOT match inside lawsuitability", () => {
    const b = new ScopeBoundary({ resources: { escalation_keywords: ["lawsuit"] } });
    assert.deepEqual(b.matchEscalationKeywords("lawsuitability analysis"), []);
  });

  it("refund matches at boundary", () => {
    const b = new ScopeBoundary({ resources: { escalation_keywords: ["refund"] } });
    assert.deepEqual(b.matchEscalationKeywords("request-refund-now"), ["refund"]);
  });

  it("blocked keyword boundary rejects partial words", () => {
    const b = new ScopeBoundary({ resources: { blocked_keywords: ["confidential"] } });
    // "nonconfidential" (no separator) should NOT match
    assert.deepEqual(b.matchBlockedKeywords("nonconfidential doc"), []);
    // "non-confidential" (hyphen separator) DOES match since hyphen is a boundary
    assert.deepEqual(b.matchBlockedKeywords("non-confidential-doc"), ["confidential"]);
  });
});

// ---------------------------------------------------------------------------
// v3: MCP server glob matching
// ---------------------------------------------------------------------------

describe("v3 MCP server glob matching", () => {
  it("exact match works", () => {
    const b = new ScopeBoundary({ org_boundary: { allowed_mcp_servers: ["hubspot"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__hubspot__get_deal", {});
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });

  it("glob pattern works", () => {
    const b = new ScopeBoundary({ org_boundary: { allowed_mcp_servers: ["notion_*"] } });
    const checker = new ScopeChecker(b);
    const r1 = checker.check("mcp__notion_prod__get_page", {});
    assert.equal(r1.verdict, CheckVerdict.ALLOW);
    const r2 = checker.check("mcp__notion_staging__get_page", {});
    assert.equal(r2.verdict, CheckVerdict.ALLOW);
  });

  it("exact match rejects partial", () => {
    const b = new ScopeBoundary({ org_boundary: { allowed_mcp_servers: ["notion"] } });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__notion_prod__get_page", {});
    assert.equal(r.verdict, CheckVerdict.BLOCK);
  });
});

// ---------------------------------------------------------------------------
// v3: CJK keyword boundary matching
// ---------------------------------------------------------------------------

describe("v3 CJK keyword matching", () => {
  it("matches Chinese keyword via substring", () => {
    const b = new ScopeBoundary({
      resources: { escalation_keywords: ["机密"] },
    });
    assert.deepEqual(b.matchEscalationKeywords("这份文件是机密信息"), ["机密"]);
  });

  it("matches Japanese keyword via substring", () => {
    const b = new ScopeBoundary({
      resources: { blocked_keywords: ["秘密"] },
    });
    assert.deepEqual(b.matchBlockedKeywords("これは秘密です"), ["秘密"]);
  });

  it("matches Korean keyword via substring", () => {
    const b = new ScopeBoundary({
      resources: { escalation_keywords: ["비밀"] },
    });
    assert.deepEqual(b.matchEscalationKeywords("이 문서는 비밀입니다"), ["비밀"]);
  });

  it("does not match CJK keyword when absent", () => {
    const b = new ScopeBoundary({
      resources: { blocked_keywords: ["機密"] },
    });
    assert.deepEqual(b.matchBlockedKeywords("公開文書です"), []);
  });
});

// ---------------------------------------------------------------------------
// v3: MCP resource rules (per-server operation control)
// ---------------------------------------------------------------------------

describe("v3 MCP resource rules", () => {
  it("blocked operation is BLOCK", () => {
    const b = new ScopeBoundary({
      org_boundary: {
        mcp_resource_rules: [{ server: "sap", blocked_operations: ["fi_*"] }],
      },
    });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__sap__fi_post_journal", {});
    assert.equal(r.verdict, CheckVerdict.BLOCK);
    assert.ok(r.reason.includes("not allowed"));
  });

  it("allowed operation passes", () => {
    const b = new ScopeBoundary({
      org_boundary: {
        mcp_resource_rules: [{ server: "sap", allowed_operations: ["mm_*"] }],
      },
    });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__sap__mm_create_po", {});
    // mm_create_po is allowed but "create" is a write verb → WARN (not BLOCK)
    assert.notEqual(r.verdict, CheckVerdict.BLOCK);
  });

  it("non-matching server has no effect", () => {
    const b = new ScopeBoundary({
      org_boundary: {
        mcp_resource_rules: [{ server: "sap", blocked_operations: ["fi_*"] }],
      },
    });
    const checker = new ScopeChecker(b);
    const r = checker.check("mcp__hubspot__get_deal", {});
    assert.equal(r.verdict, CheckVerdict.ALLOW);
  });
});

// ---------------------------------------------------------------------------
// v3: New content patterns
// ---------------------------------------------------------------------------

describe("v3 ContentScanner new patterns", () => {
  const scanner = new ContentScanner();

  it("detects IBAN", () => {
    const r = scanner.scan("IBAN: DE89 3704 0044 0532 0130 00");
    assert.ok(r.flags.some(f => f.pattern_name === "iban"));
  });

  it("detects medication dosage", () => {
    const r = scanner.scan("dose: 500 mg daily");
    assert.ok(r.flags.some(f => f.pattern_name === "medication_dosage"));
  });

  it("detects lab result", () => {
    const r = scanner.scan("glucose: 120 mg/dL");
    assert.ok(r.flags.some(f => f.pattern_name === "lab_result"));
  });

  it("detects salary keyword with context", () => {
    const r = scanner.scan("employee salary: $150000");
    assert.ok(r.flags.some(f => f.pattern_name === "salary_keyword"));
  });

  it("does NOT flag salary in job posting", () => {
    const r = scanner.scan("salary range: $120k-$180k per our job posting");
    // "salary range" lacks required prefix (employee/your/annual/base)
    assert.ok(!r.flags.some(f => f.pattern_name === "salary_keyword"));
  });

  it("detects tariff code", () => {
    const r = scanner.scan("HTS: 8471.30.0100");
    assert.ok(r.flags.some(f => f.pattern_name === "tariff_code"));
  });

  it("detects privilege marker", () => {
    const r = scanner.scan("This document is PRIVILEGED AND CONFIDENTIAL");
    assert.ok(r.flags.some(f => f.pattern_name === "privilege_marker"));
  });

  it("does NOT flag privileged user (IT term)", () => {
    const r = scanner.scan("The privileged user logged in via SSH");
    assert.ok(!r.flags.some(f => f.pattern_name === "privilege_marker"));
  });
});

// ---------------------------------------------------------------------------
// v3: Industry risk rules
// ---------------------------------------------------------------------------

describe("v3 industry risk rules", () => {
  const engine = RiskEngine.default();

  it("clinical_order HIGH", () => {
    assert.equal(engine.assess("mcp__epic__prescribe", {}), RiskLevel.HIGH);
  });

  it("procurement_order HIGH", () => {
    assert.equal(engine.assess("mcp__sap__purchase_order", {}), RiskLevel.HIGH);
  });

  it("shipment_divert HIGH", () => {
    assert.equal(engine.assess("mcp__logistics__reroute", {}), RiskLevel.HIGH);
  });

  it("termination_ops HIGH", () => {
    assert.equal(engine.assess("mcp__workday__offboard", {}), RiskLevel.HIGH);
  });

  it("litigation_hold HIGH", () => {
    assert.equal(engine.assess("mcp__legal__delete_hold", {}), RiskLevel.HIGH);
  });

  it("iac_destructive HIGH", () => {
    assert.equal(engine.assess("Bash", { command: "terraform destroy -auto-approve" }), RiskLevel.HIGH);
  });

  it("payment_release HIGH", () => {
    assert.equal(engine.assess("mcp__stripe__create_payout", {}), RiskLevel.HIGH);
  });

  it("social_media_post HIGH", () => {
    assert.equal(engine.assess("mcp__twitter__create_tweet", {}), RiskLevel.HIGH);
  });

  it("iac_apply MEDIUM (terraform apply)", () => {
    assert.equal(engine.assess("Bash", { command: "terraform apply -auto-approve" }), RiskLevel.MEDIUM);
  });

  it("crm_merge_ops HIGH (merge_contact)", () => {
    assert.equal(engine.assess("mcp__hubspot__merge_contact", {}), RiskLevel.HIGH);
  });

  it("enrollment_mass HIGH (add_to_sequence)", () => {
    assert.equal(engine.assess("mcp__hubspot__add_to_sequence", {}), RiskLevel.HIGH);
  });

  it("marketing_list_destruct HIGH (bulk_unsubscribe)", () => {
    assert.equal(engine.assess("mcp__mailchimp__bulk_unsubscribe", {}), RiskLevel.HIGH);
  });

  it("inventory_adjust HIGH", () => {
    assert.equal(engine.assess("mcp__sap__inventory_adjust", {}), RiskLevel.HIGH);
  });

  it("financial_reversal HIGH (void check)", () => {
    assert.equal(engine.assess("mcp__netsuite__void_check", {}), RiskLevel.HIGH);
  });

  it("tax_adjustment HIGH", () => {
    assert.equal(engine.assess("mcp__sap__tax_reversal", {}), RiskLevel.HIGH);
  });

  it("support_bulk_ops HIGH (bulk_assign)", () => {
    assert.equal(engine.assess("mcp__zendesk__bulk_assign", {}), RiskLevel.HIGH);
  });

  it("clinical_procedure HIGH (schedule_surgery)", () => {
    assert.equal(engine.assess("mcp__epic__schedule_surgery", {}), RiskLevel.HIGH);
  });

  it("helm upgrade triggers iac_apply MEDIUM", () => {
    assert.equal(engine.assess("Bash", { command: "helm upgrade my-release ./chart" }), RiskLevel.MEDIUM);
  });

  it("kubectl apply triggers iac_apply MEDIUM", () => {
    assert.equal(engine.assess("Bash", { command: "kubectl apply -f deployment.yaml" }), RiskLevel.MEDIUM);
  });
});

// ---------------------------------------------------------------------------
// v3: Params summary in audit
// ---------------------------------------------------------------------------

describe("v3 audit params_summary", () => {
  it("MCP check includes params_summary", () => {
    const checker = new ScopeChecker(new ScopeBoundary());
    const r = checker.check("mcp__stripe__create_charge", { amount: 5000, customer_id: "cus_123" });
    assert.ok(r.params_summary);
    assert.equal(r.params_summary!.mcp_server, "stripe");
    assert.equal(r.params_summary!.mcp_operation, "create_charge");
    assert.equal(r.params_summary!.transaction_amount, "5000");
    assert.ok(r.params_summary!.resource_id_hash);
    assert.equal(r.params_summary!.resource_id_hash!.length, 16); // truncated hash
  });

  it("audit record persists MCP context", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-v3-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({
      verdict: CheckVerdict.WARN,
      tool: "mcp__stripe__create_charge",
      target: "",
      reason: "write op",
      risk_level: RiskLevel.MEDIUM,
      scope_violation: false,
      params_summary: {
        mcp_server: "stripe",
        mcp_operation: "create_charge",
        resource_id_hash: "abc123def456",
        transaction_amount: "5000",
        operation_scope: "single",
      },
    });
    const entries = log.read();
    assert.equal(entries[0].mcp_server, "stripe");
    assert.equal(entries[0].mcp_operation, "create_charge");
    assert.equal(entries[0].resource_id_hash, "abc123def456");
    assert.equal(entries[0].transaction_amount, "5000");
    assert.equal(entries[0].operation_scope, "single");
    rmSync(tmp, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// v3: Audit export with redaction
// ---------------------------------------------------------------------------

describe("v3 audit export", () => {
  it("export without redaction includes HMAC", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-exp-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.ALLOW, tool: "Read", target: "f.ts", reason: "", risk_level: RiskLevel.LOW, scope_violation: false });
    const exported = log.export();
    assert.ok(exported.includes("hmac"));
    rmSync(tmp, { recursive: true });
  });

  it("export with redaction strips HMAC and redacts sensitive target", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-exp-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({ verdict: CheckVerdict.WARN, tool: "Read", target: "SSN: 123-45-6789", reason: "", risk_level: RiskLevel.HIGH, scope_violation: false });
    const exported = log.export({ redact: true });
    assert.ok(!exported.includes("123-45-6789"));
    assert.ok(exported.includes("[REDACTED:ssn]"));
    assert.ok(!exported.includes('"hmac"'));
    rmSync(tmp, { recursive: true });
  });

  it("export with redaction strips sensitive data from transaction_amount", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-audit-exp-"));
    const p = join(tmp, "audit.jsonl");
    const log = new AuditLog(p);
    log.record({
      verdict: CheckVerdict.WARN,
      tool: "mcp__stripe__create_charge",
      target: "customer SSN: 123-45-6789",
      reason: "write op",
      risk_level: RiskLevel.MEDIUM,
      scope_violation: false,
      params_summary: {
        mcp_server: "stripe",
        mcp_operation: "create_charge",
        resource_id_hash: "abc123def456",
        transaction_amount: "5000",
        operation_scope: "single",
      },
    });
    const exported = log.export({ redact: true });
    // Target should be redacted
    assert.ok(!exported.includes("123-45-6789"));
    // MCP context should be preserved (not sensitive)
    assert.ok(exported.includes("stripe"));
    assert.ok(exported.includes("create_charge"));
    // resource_id_hash is already hashed, safe to keep
    assert.ok(exported.includes("abc123def456"));
    rmSync(tmp, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// v3: Compliance presets
// ---------------------------------------------------------------------------

describe("v3 compliance presets", () => {
  it("clinical preset includes HIPAA + clinical rules", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-pol-"));
    const p = join(tmp, "policy.json");
    writeFileSync(p, JSON.stringify({ compliance_mode: "clinical" }));
    const loaded = loadPolicy(p);
    assert.equal(loaded.require_scope_boundary, true);
    assert.ok(loaded.extra_rules!.some(r => r.name === "hipaa_phi_export"));
    assert.ok(loaded.extra_rules!.some(r => r.name === "clinical_medication_order"));
    rmSync(tmp, { recursive: true });
  });

  it("hr preset has termination rule", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-pol-"));
    const p = join(tmp, "policy.json");
    writeFileSync(p, JSON.stringify({ compliance_mode: "hr" }));
    const loaded = loadPolicy(p);
    assert.ok(loaded.extra_rules!.some(r => r.name === "hr_termination"));
    rmSync(tmp, { recursive: true });
  });

  it("research preset allows MEDIUM auto-allow", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-pol-"));
    const p = join(tmp, "policy.json");
    writeFileSync(p, JSON.stringify({ compliance_mode: "research" }));
    const loaded = loadPolicy(p);
    assert.equal(loaded.max_risk_auto_allow, "medium");
    rmSync(tmp, { recursive: true });
  });

  it("supply_chain_sap preset has SAP transaction codes", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sg-pol-"));
    const p = join(tmp, "policy.json");
    writeFileSync(p, JSON.stringify({ compliance_mode: "supply_chain_sap" }));
    const loaded = loadPolicy(p);
    assert.ok(loaded.extra_rules!.some(r => r.name === "sap_mm_mutation"));
    rmSync(tmp, { recursive: true });
  });
});
