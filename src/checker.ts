/**
 * ScopeChecker — the core engine that decides allow / warn / block for every tool call.
 */

import { RiskEngine, RiskLevel, riskOrd } from "./risk.js";
import { ScopeBoundary } from "./scope.js";

export enum CheckVerdict {
  ALLOW = "allow",
  WARN = "warn",
  BLOCK = "block",
}

export interface CheckResult {
  verdict: CheckVerdict;
  tool: string;
  target: string;
  reason: string;
  risk_level: RiskLevel;
  scope_violation: boolean;
}

/** Tools that read but don't modify — always allow. */
const READ_ONLY_TOOLS = new Set([
  "Read", "Glob", "Grep", "WebSearch", "WebFetch",
  "TodoWrite", "AskUserQuestion",
]);

/** Tools where we extract a file path to check scope. */
const FILE_PATH_TOOLS = new Set(["Edit", "Write", "NotebookEdit"]);

export class ScopeChecker {
  readonly boundary: ScopeBoundary;
  readonly riskEngine: RiskEngine;

  constructor(boundary: ScopeBoundary, riskEngine?: RiskEngine) {
    this.boundary = boundary;
    this.riskEngine = riskEngine ?? RiskEngine.default();
  }

  check(toolName: string, params: Record<string, unknown>): CheckResult {
    // 0. Empty or missing tool name — warn, not silently allow.
    if (!toolName) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target: "",
        reason: "empty or missing tool name",
        risk_level: RiskLevel.LOW,
        scope_violation: false,
      };
    }

    // 1. Read-only tools are always allowed.
    if (READ_ONLY_TOOLS.has(toolName)) {
      return {
        verdict: CheckVerdict.ALLOW,
        tool: toolName,
        target: "",
        reason: "read-only tool",
        risk_level: RiskLevel.LOW,
        scope_violation: false,
      };
    }

    // 2. If no scope boundary is set, fall back to risk-only check.
    if (this.boundary.isEmpty) {
      const risk = this.riskEngine.assess(toolName, params);
      return this.riskOnlyResult(toolName, params, risk);
    }

    // 3. File-path tools: check scope + risk.
    if (FILE_PATH_TOOLS.has(toolName)) {
      return this.checkFileTool(toolName, params);
    }

    // 4. Bash: check risk.
    if (toolName === "Bash") {
      return this.checkBash(toolName, params);
    }

    // 5. Everything else: risk-only.
    const risk = this.riskEngine.assess(toolName, params);
    return this.riskOnlyResult(toolName, params, risk);
  }

  private checkFileTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const filePath = (params.file_path ?? params.notebook_path ?? "") as string;
    const risk = this.riskEngine.assess(toolName, params);

    if (!filePath) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target: "",
        reason: "no file path detected — cannot verify scope",
        risk_level: risk,
        scope_violation: false,
      };
    }

    const inScope = this.boundary.isFileInScope(filePath);

    if (inScope) {
      const verdict = verdictForRisk(risk);
      return {
        verdict,
        tool: toolName,
        target: filePath,
        reason: verdict === CheckVerdict.ALLOW ? "in scope" : `in scope but ${risk} risk`,
        risk_level: risk,
        scope_violation: false,
      };
    }

    // Out of scope — at minimum warn, block if high risk.
    const verdict = risk === RiskLevel.HIGH ? CheckVerdict.BLOCK : CheckVerdict.WARN;
    return {
      verdict,
      tool: toolName,
      target: filePath,
      reason: `out of scope (${filePath})`,
      risk_level: risk,
      scope_violation: true,
    };
  }

  private checkBash(toolName: string, params: Record<string, unknown>): CheckResult {
    const command = ((params.command as string) ?? "").slice(0, 500);
    const risk = this.riskEngine.assess(toolName, params);

    if (risk === RiskLevel.HIGH) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target: command,
        reason: "high-risk shell command",
        risk_level: risk,
        scope_violation: false,
      };
    }

    if (risk === RiskLevel.MEDIUM) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target: command,
        reason: "medium-risk shell command",
        risk_level: risk,
        scope_violation: false,
      };
    }

    return {
      verdict: CheckVerdict.ALLOW,
      tool: toolName,
      target: command,
      reason: "low-risk shell command",
      risk_level: risk,
      scope_violation: false,
    };
  }

  private riskOnlyResult(
    toolName: string,
    params: Record<string, unknown>,
    risk: RiskLevel,
  ): CheckResult {
    return {
      verdict: verdictForRisk(risk),
      tool: toolName,
      target: extractTarget(toolName, params),
      reason: `${risk} risk`,
      risk_level: risk,
      scope_violation: false,
    };
  }
}

function verdictForRisk(risk: RiskLevel): CheckVerdict {
  if (risk === RiskLevel.HIGH) return CheckVerdict.BLOCK;
  if (risk === RiskLevel.MEDIUM) return CheckVerdict.WARN;
  return CheckVerdict.ALLOW;
}

function extractTarget(toolName: string, params: Record<string, unknown>): string {
  for (const key of ["file_path", "notebook_path", "command", "pattern", "url", "query"]) {
    const val = params[key];
    if (val != null && val !== "") return String(val).slice(0, 500);
  }
  return "";
}
