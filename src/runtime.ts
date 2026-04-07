import { isAbsolute, join } from "node:path";
import { ScopeChecker } from "./checker.js";
import { buildRiskEngine, loadPolicy, type PolicyConfig } from "./policy.js";
import { ScopeBoundary } from "./scope.js";

export interface RuntimePaths {
  scopePath?: string;
  policyPath?: string;
  auditLogPath?: string;
}

export interface EnforcementRuntime {
  scopePath: string;
  policyPath: string;
  auditLogPath: string;
  boundary: ScopeBoundary;
  policy: PolicyConfig;
  checker: ScopeChecker;
}

export function resolveWorkspacePath(
  workspacePath: string,
  configuredPath: string | undefined,
  fallbackRelativePath: string,
): string {
  if (!configuredPath) return join(workspacePath, fallbackRelativePath);
  return isAbsolute(configuredPath) ? configuredPath : join(workspacePath, configuredPath);
}

export function loadEnforcementRuntime(
  workspacePath: string,
  paths?: RuntimePaths,
): EnforcementRuntime {
  const scopePath = resolveWorkspacePath(
    workspacePath,
    paths?.scopePath,
    join(".claude", "scope-boundary.json"),
  );
  const policyPath = resolveWorkspacePath(
    workspacePath,
    paths?.policyPath,
    join(".claude", "scope-guard-policy.json"),
  );
  const auditLogPath = resolveWorkspacePath(
    workspacePath,
    paths?.auditLogPath,
    join(".claude", "scope-guard-audit.jsonl"),
  );

  const boundary = ScopeBoundary.load(scopePath);
  const policy = loadPolicy(policyPath);
  const checker = new ScopeChecker(boundary, buildRiskEngine(policy), undefined, policy);

  return {
    scopePath,
    policyPath,
    auditLogPath,
    boundary,
    policy,
    checker,
  };
}
