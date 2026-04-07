/**
 * ScopeChecker v2 — 4-verdict engine (ALLOW / WARN / ESCALATE / BLOCK)
 * with MCP tool classification, resource scoping, and content scanning.
 */

import { RiskEngine, RiskLevel, riskOrd } from "./risk.js";
import { ScopeBoundary } from "./scope.js";
import { ContentScanner } from "./content.js";

export enum CheckVerdict {
  ALLOW = "allow",
  WARN = "warn",
  ESCALATE = "escalate",
  BLOCK = "block",
}

export interface CheckResult {
  verdict: CheckVerdict;
  tool: string;
  target: string;
  reason: string;
  risk_level: RiskLevel;
  scope_violation: boolean;
  escalation_reason?: string;
  matched_rules?: string[];
  content_flags?: string[];
}

/** Tools that are truly inert — always allow without any check. */
const SAFE_TOOLS = new Set(["TodoWrite", "AskUserQuestion"]);

/** Tools that read but don't modify — allow by default but scan for sensitive content. */
const READ_TOOLS = new Set(["Read", "Glob", "Grep", "WebSearch", "WebFetch"]);

/** Tools where we extract a file path to check scope. */
const FILE_PATH_TOOLS = new Set(["Edit", "Write", "NotebookEdit"]);

/**
 * Write verbs for MCP tool classification.
 * Covers CRUD, communication, state changes, scheduling, execution, and data ops.
 */
const MCP_WRITE_VERBS = new RegExp(
  "(?:^|_)(" + [
    "create", "update", "delete", "remove", "add", "set", "put",
    "post", "patch", "push", "send", "publish", "broadcast", "notify", "reply",
    "close", "resolve", "approve", "reject", "assign", "merge",
    "submit", "cancel", "revoke", "grant",
    "schedule", "queue", "enqueue", "activate", "launch",
    "enable", "disable",
    "start", "execute", "run", "dispense", "transfer",
    "insert", "move", "write", "fork",
  ].join("|") + ")(?:_|$)",
  "i",
);

function parseMcpTool(toolName: string): { server: string; operation: string } | null {
  const parts = toolName.split("__");
  if (parts.length < 3 || parts[0] !== "mcp") return null;
  return { server: parts.slice(1, -1).join("__"), operation: parts[parts.length - 1] };
}

export class ScopeChecker {
  readonly boundary: ScopeBoundary;
  readonly riskEngine: RiskEngine;
  readonly scanner: ContentScanner;

  constructor(boundary: ScopeBoundary, riskEngine?: RiskEngine, scanner?: ContentScanner) {
    this.boundary = boundary;
    this.riskEngine = riskEngine ?? RiskEngine.default();
    this.scanner = scanner ?? new ContentScanner();
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

    // 1. Inert tools — always allow.
    if (SAFE_TOOLS.has(toolName)) {
      return {
        verdict: CheckVerdict.ALLOW,
        tool: toolName,
        target: "",
        reason: "safe tool",
        risk_level: RiskLevel.LOW,
        scope_violation: false,
      };
    }

    // 2. Read tools — allow but scan for sensitive content + check resource scope.
    if (READ_TOOLS.has(toolName)) {
      return this.checkReadTool(toolName, params);
    }

    // 3. MCP tools — classify by verb + check org boundary + resource scope.
    if (toolName.startsWith("mcp__")) {
      return this.checkMcpTool(toolName, params);
    }

    // 4. File-path tools: check scope + risk (or risk-only if no boundary).
    if (FILE_PATH_TOOLS.has(toolName)) {
      if (this.boundary.isEmpty) {
        const risk = this.riskEngine.assess(toolName, params);
        return this.riskOnlyResult(toolName, params, risk);
      }
      return this.checkFileTool(toolName, params);
    }

    // 5. Bash: check risk (scope boundary not needed).
    if (toolName === "Bash") {
      return this.checkBash(toolName, params);
    }

    // 7. Everything else: unknown tool — minimum WARN for safety.
    const risk = this.riskEngine.assess(toolName, params);
    const effectiveRisk = riskOrd(risk) >= riskOrd(RiskLevel.MEDIUM) ? risk : RiskLevel.MEDIUM;
    return {
      verdict: verdictForRisk(effectiveRisk),
      tool: toolName,
      target: extractTarget(toolName, params),
      reason: `unknown tool — elevated to ${effectiveRisk} risk for safety`,
      risk_level: effectiveRisk,
      scope_violation: false,
    };
  }

  private checkReadTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const target = extractTarget(toolName, params);

    // protected_resources check — even reads are blocked
    if (this.boundary.resources?.protected_resources?.length) {
      const status = this.boundary.isResourceAllowed(target);
      if (status === "protected") {
        return {
          verdict: CheckVerdict.BLOCK,
          tool: toolName,
          target,
          reason: `protected resource — read access denied`,
          risk_level: RiskLevel.HIGH,
          scope_violation: true,
        };
      }
    }

    // escalation keywords check
    const escKeywords = this.boundary.matchEscalationKeywords(target);
    if (escKeywords.length > 0) {
      return {
        verdict: CheckVerdict.ESCALATE,
        tool: toolName,
        target,
        reason: `escalation keyword detected: ${escKeywords.join(", ")}`,
        risk_level: RiskLevel.HIGH,
        scope_violation: false,
        escalation_reason: `Content matches escalation keywords: ${escKeywords.join(", ")}`,
      };
    }

    // Content scan on params
    const scan = this.scanner.scan(target);
    if (scan.flags.length > 0 && scan.highest_risk === RiskLevel.HIGH) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target,
        reason: `sensitive content in read target: ${scan.flags.map(f => f.pattern_name).join(", ")}`,
        risk_level: scan.highest_risk,
        scope_violation: false,
        content_flags: scan.flags.map(f => f.pattern_name),
      };
    }

    return {
      verdict: CheckVerdict.ALLOW,
      tool: toolName,
      target: "",
      reason: "read-only tool",
      risk_level: RiskLevel.LOW,
      scope_violation: false,
    };
  }

  private checkMcpTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const parsed = parseMcpTool(toolName);
    const target = extractTarget(toolName, params);
    const risk = this.riskEngine.assess(toolName, params);
    const matchedRules = this.riskEngine.matchingRules(toolName, params).map(r => r.name);

    // 1. OrgBoundary: server allow/block list
    if (parsed && !this.boundary.isMcpServerAllowed(parsed.server)) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target,
        reason: `MCP server "${parsed.server}" not in allowed list — configure org_boundary in scope-boundary.json`,
        risk_level: RiskLevel.HIGH,
        scope_violation: true,
        matched_rules: matchedRules,
      };
    }

    // 2. Escalation keywords in params
    const paramsStr = JSON.stringify(params);
    const escKeywords = this.boundary.matchEscalationKeywords(paramsStr);
    if (escKeywords.length > 0) {
      return {
        verdict: CheckVerdict.ESCALATE,
        tool: toolName,
        target,
        reason: `escalation keyword in params: ${escKeywords.join(", ")}`,
        risk_level: RiskLevel.HIGH,
        scope_violation: false,
        escalation_reason: `MCP call contains escalation keywords: ${escKeywords.join(", ")}`,
        matched_rules: matchedRules,
      };
    }

    // 3. Blocked keywords in params
    const blockedKw = this.boundary.matchBlockedKeywords(paramsStr);
    if (blockedKw.length > 0) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target,
        reason: `blocked keyword in params: ${blockedKw.join(", ")}`,
        risk_level: RiskLevel.MEDIUM,
        scope_violation: false,
        matched_rules: matchedRules,
      };
    }

    // 4. Content scan on params
    const scan = this.scanner.scan(paramsStr);
    const contentFlags = scan.flags.length > 0 ? scan.flags.map(f => f.pattern_name) : undefined;

    // 5. Write verb detection
    const isWrite = parsed ? MCP_WRITE_VERBS.test(parsed.operation) : false;

    if (isWrite) {
      // Write operations: minimum MEDIUM, risk rules can escalate further
      const effectiveRisk = riskOrd(risk) > riskOrd(RiskLevel.MEDIUM) ? risk : RiskLevel.MEDIUM;
      const verdict = riskOrd(effectiveRisk) >= riskOrd(RiskLevel.HIGH)
        ? CheckVerdict.BLOCK
        : CheckVerdict.WARN;
      return {
        verdict,
        tool: toolName,
        target,
        reason: `MCP write operation "${parsed?.operation}" — ${effectiveRisk} risk`,
        risk_level: effectiveRisk,
        scope_violation: false,
        matched_rules: matchedRules,
        content_flags: contentFlags,
      };
    }

    // 6. Read operation — still run risk assessment on params
    if (risk !== RiskLevel.LOW) {
      return {
        verdict: verdictForRisk(risk),
        tool: toolName,
        target,
        reason: `MCP read but ${risk} risk detected in params`,
        risk_level: risk,
        scope_violation: false,
        matched_rules: matchedRules,
        content_flags: contentFlags,
      };
    }

    return {
      verdict: CheckVerdict.ALLOW,
      tool: toolName,
      target,
      reason: "MCP read operation",
      risk_level: RiskLevel.LOW,
      scope_violation: false,
      content_flags: contentFlags,
    };
  }

  private checkFileTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const filePath = (params.file_path ?? params.notebook_path ?? "") as string;
    const risk = this.riskEngine.assess(toolName, params);

    if (!filePath) {
      return {
        verdict: CheckVerdict.WARN,
        tool: toolName,
        target: "",
        reason: "no file path detected — cannot verify scope. Provide file_path to proceed",
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
        reason: verdict === CheckVerdict.ALLOW ? "in scope" : verdict === CheckVerdict.BLOCK ? `in scope but ${risk} risk — requires explicit user confirmation` : `in scope but ${risk} risk`,
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
      reason: `out of scope (${filePath}) — edit .claude/scope-boundary.json to expand scope`,
      risk_level: risk,
      scope_violation: true,
    };
  }

  private checkBash(toolName: string, params: Record<string, unknown>): CheckResult {
    const command = ((params.command as string) ?? "").slice(0, 500);
    const risk = this.riskEngine.assess(toolName, params);
    const matchedRules = this.riskEngine.matchingRules(toolName, params).map(r => r.name);

    if (risk === RiskLevel.HIGH) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target: command,
        reason: "high-risk shell command — requires explicit user confirmation to proceed",
        risk_level: risk,
        scope_violation: false,
        matched_rules: matchedRules,
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
        matched_rules: matchedRules,
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
  for (const key of ["file_path", "notebook_path", "command", "pattern", "url", "query", "sql"]) {
    const val = params[key];
    if (val != null && val !== "") return String(val).slice(0, 500);
  }
  return "";
}
