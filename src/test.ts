/**
 * Scope Guard — test suite using Node built-in test runner.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { RiskLevel, RiskRule, RiskEngine, builtinRules } from "./risk.js";
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

describe("RiskEngine", () => {
  const engine = RiskEngine.default();

  it("rm -rf is HIGH", () => assert.equal(engine.assess("Bash", { command: "rm -rf /tmp" }), RiskLevel.HIGH));
  it("git push --force is HIGH", () => assert.equal(engine.assess("Bash", { command: "git push --force" }), RiskLevel.HIGH));
  it("git push -f is HIGH", () => assert.equal(engine.assess("Bash", { command: "git push -f" }), RiskLevel.HIGH));
  it("git reset --hard is HIGH", () => assert.equal(engine.assess("Bash", { command: "git reset --hard" }), RiskLevel.HIGH));
  it("drop table is HIGH", () => assert.equal(engine.assess("Bash", { command: "drop table users" }), RiskLevel.HIGH));
  it(".env file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: ".env" }), RiskLevel.HIGH));
  it(".pem file is HIGH", () => assert.equal(engine.assess("Edit", { file_path: "key.pem" }), RiskLevel.HIGH));
  it("curl POST is HIGH", () => assert.equal(engine.assess("Bash", { command: "curl -X POST http://a" }), RiskLevel.HIGH));
  it("npm publish is HIGH", () => assert.equal(engine.assess("Bash", { command: "npm publish" }), RiskLevel.HIGH));
  it("docker push is HIGH", () => assert.equal(engine.assess("Bash", { command: "docker push img" }), RiskLevel.HIGH));
  it("rmdir is HIGH", () => assert.equal(engine.assess("Bash", { command: "rmdir /tmp/foo" }), RiskLevel.HIGH));
  it("wget --post is HIGH", () => assert.equal(engine.assess("Bash", { command: "wget --post-data=x http://a" }), RiskLevel.HIGH));

  it("Write tool is MEDIUM", () => assert.equal(engine.assess("Write", { file_path: "foo.ts" }), RiskLevel.MEDIUM));
  it("curl get is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "curl http://a" }), RiskLevel.MEDIUM));
  it("pip install is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "pip install x" }), RiskLevel.MEDIUM));
  it("npm install is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "npm install x" }), RiskLevel.MEDIUM));
  it("chmod is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "chmod 755 f" }), RiskLevel.MEDIUM));
  it("git checkout -- is MEDIUM", () => assert.equal(engine.assess("Bash", { command: "git checkout -- ." }), RiskLevel.MEDIUM));

  it("ls is LOW", () => assert.equal(engine.assess("Bash", { command: "ls -la" }), RiskLevel.LOW));
  it("echo is LOW", () => assert.equal(engine.assess("Bash", { command: "echo hi" }), RiskLevel.LOW));
  it("Read tool is LOW", () => assert.equal(engine.assess("Read", { file_path: "f.ts" }), RiskLevel.LOW));

  it("builtin rules count is 13", () => assert.equal(builtinRules().length, 13));
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

  it("normalise collapses ./", () => {
    assert.equal(normalisePath("./src/foo.ts"), normalisePath("src/foo.ts"));
  });

  it("expand scope", () => {
    const b = new ScopeBoundary({ files_in_scope: ["a.ts"] });
    b.expandScope(["b.ts"], undefined, "test");
    assert.equal(b.files_in_scope.length, 2);
    assert.equal(b.revisions.length, 1);
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

  it("Read is always ALLOW", () => {
    assert.equal(checker.check("Read", { file_path: "/etc/passwd" }).verdict, CheckVerdict.ALLOW);
  });

  it("Glob is always ALLOW", () => {
    assert.equal(checker.check("Glob", {}).verdict, CheckVerdict.ALLOW);
  });

  it("TodoWrite is always ALLOW", () => {
    assert.equal(checker.check("TodoWrite", {}).verdict, CheckVerdict.ALLOW);
  });

  it("Edit in scope = ALLOW", () => {
    assert.equal(checker.check("Edit", { file_path: "src/auth/login.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("Edit in scope dir = ALLOW", () => {
    assert.equal(checker.check("Edit", { file_path: "src/auth/utils.ts" }).verdict, CheckVerdict.ALLOW);
  });

  it("Edit out of scope = WARN", () => {
    const r = checker.check("Edit", { file_path: "src/api/routes.ts" });
    assert.equal(r.verdict, CheckVerdict.WARN);
    assert.equal(r.scope_violation, true);
  });

  it("Edit .env out of scope = BLOCK", () => {
    assert.equal(checker.check("Edit", { file_path: ".env" }).verdict, CheckVerdict.BLOCK);
  });

  it("Bash low risk = ALLOW", () => {
    assert.equal(checker.check("Bash", { command: "ls" }).verdict, CheckVerdict.ALLOW);
  });

  it("Bash medium risk = WARN", () => {
    assert.equal(checker.check("Bash", { command: "curl http://x" }).verdict, CheckVerdict.WARN);
  });

  it("Bash high risk = BLOCK", () => {
    assert.equal(checker.check("Bash", { command: "rm -rf /" }).verdict, CheckVerdict.BLOCK);
  });

  it("Write with no file_path = WARN", () => {
    assert.equal(checker.check("Write", {}).verdict, CheckVerdict.WARN);
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
});
