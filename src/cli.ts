#!/usr/bin/env node
/**
 * Scope Guard CLI — developer experience tools.
 *
 * Usage:
 *   scope-guard --dry-run <tool> [params-json]   Simulate a tool call check
 *   scope-guard --validate [policy-path]          Validate scope boundary + policy
 *   scope-guard --verify-audit [audit-path]       Verify audit log integrity
 *   scope-guard --summary [audit-path]            Show audit log summary
 */

import { join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { RiskEngine } from "./risk.js";
import { ScopeBoundary } from "./scope.js";
import { AuditLog } from "./audit.js";
import { loadPolicy, buildRiskEngine, validatePolicy } from "./policy.js";

const args = process.argv.slice(2);

function usage(): void {
  console.log(`scope-guard CLI — developer experience tools

Usage:
  scope-guard --dry-run <tool> [params-json]   Simulate a tool call check
  scope-guard --validate [policy-path]          Validate scope boundary + policy
  scope-guard --verify-audit [audit-path]       Verify audit log integrity
  scope-guard --summary [audit-path]            Show audit log summary
  scope-guard --help                            Show this help`);
}

function dryRun(tool: string, paramsStr?: string): void {
  const cwd = process.cwd();
  const scopePath = join(cwd, ".claude", "scope-boundary.json");
  const policyPath = join(cwd, ".claude", "scope-guard-policy.json");

  const boundary = ScopeBoundary.load(scopePath);

  let engine: RiskEngine;
  if (existsSync(policyPath)) {
    const policy = loadPolicy(policyPath);
    engine = buildRiskEngine(policy);
  } else {
    engine = RiskEngine.default();
  }

  let params: Record<string, unknown> = {};
  if (paramsStr) {
    try {
      params = JSON.parse(paramsStr);
    } catch {
      console.error("Error: params must be valid JSON");
      process.exit(1);
    }
  }

  const checker = new ScopeChecker(boundary, engine);
  const result = checker.check(tool, params);

  console.log(JSON.stringify(result, null, 2));

  // Exit code mirrors hook semantics
  const codes: Record<string, number> = { allow: 0, warn: 1, escalate: 2, block: 3 };
  process.exit(codes[result.verdict] ?? 3);
}

function validate(policyPath?: string): void {
  const cwd = process.cwd();
  const scopePath = join(cwd, ".claude", "scope-boundary.json");
  const resolvedPolicy = policyPath ?? join(cwd, ".claude", "scope-guard-policy.json");

  let hasErrors = false;

  // Validate scope boundary
  if (existsSync(scopePath)) {
    try {
      const raw = JSON.parse(readFileSync(scopePath, "utf-8"));
      console.log("✓ scope-boundary.json: valid JSON");
      if (raw.files_in_scope?.length || raw.dirs_in_scope?.length) {
        console.log(`  files: ${raw.files_in_scope?.length ?? 0}, dirs: ${raw.dirs_in_scope?.length ?? 0}`);
      }
      if (raw.org_boundary) {
        console.log(`  org_boundary: tenant=${raw.org_boundary.tenant_id ?? "none"}`);
      }
      if (raw.resources) {
        console.log(`  resources: ${Object.keys(raw.resources).join(", ")}`);
      }
    } catch (e) {
      console.error(`✗ scope-boundary.json: ${e}`);
      hasErrors = true;
    }
  } else {
    console.log("○ scope-boundary.json: not found (optional)");
  }

  // Validate policy
  if (existsSync(resolvedPolicy)) {
    try {
      const policy = loadPolicy(resolvedPolicy);
      const result = validatePolicy(policy);
      if (result.valid) {
        console.log("✓ policy: valid");
        if (policy.compliance_mode) console.log(`  compliance_mode: ${policy.compliance_mode}`);
        if (policy.extra_rules?.length) console.log(`  extra_rules: ${policy.extra_rules.length}`);
        if (policy.blocked_tools?.length) console.log(`  blocked_tools: ${policy.blocked_tools.join(", ")}`);
      } else {
        console.error("✗ policy: invalid");
        for (const e of result.errors) console.error(`  error: ${e}`);
        hasErrors = true;
      }
      for (const w of result.warnings) console.log(`  warning: ${w}`);
    } catch (e) {
      console.error(`✗ policy: ${e}`);
      hasErrors = true;
    }
  } else {
    console.log("○ policy: not found (optional)");
  }

  process.exit(hasErrors ? 1 : 0);
}

function verifyAudit(auditPath?: string): void {
  const resolvedPath = auditPath ?? join(process.cwd(), ".claude", "scope-guard-audit.jsonl");
  const log = new AuditLog(resolvedPath);

  if (!existsSync(resolvedPath)) {
    console.log("No audit log found.");
    process.exit(0);
    return;
  }

  const result = log.verify();
  console.log(JSON.stringify(result, null, 2));

  if (result.tampered > 0 || result.chain_breaks > 0) {
    console.error(`\nINTEGRITY FAILURE: ${result.tampered} tampered entries, ${result.chain_breaks} chain breaks`);
    process.exit(1);
  } else {
    console.log(`\nIntegrity OK: ${result.valid} valid, ${result.unsigned} unsigned`);
    process.exit(0);
  }
}

function summary(auditPath?: string): void {
  const resolvedPath = auditPath ?? join(process.cwd(), ".claude", "scope-guard-audit.jsonl");
  const log = new AuditLog(resolvedPath);

  if (!existsSync(resolvedPath)) {
    console.log("No audit log found.");
    process.exit(0);
    return;
  }

  const s = log.summary();
  console.log(JSON.stringify(s, null, 2));
}

// Route commands
if (args.includes("--help") || args.includes("-h") || args.length === 0) {
  usage();
  process.exit(0);
} else if (args[0] === "--dry-run") {
  const tool = args[1];
  if (!tool) {
    console.error("Error: --dry-run requires a tool name");
    process.exit(1);
  }
  dryRun(tool, args[2]);
} else if (args[0] === "--validate") {
  validate(args[1]);
} else if (args[0] === "--verify-audit") {
  verifyAudit(args[1]);
} else if (args[0] === "--summary") {
  summary(args[1]);
} else {
  console.error(`Unknown option: ${args[0]}`);
  usage();
  process.exit(1);
}
