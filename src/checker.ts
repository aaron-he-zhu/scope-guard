/**
 * ScopeChecker v2 — 4-verdict engine (ALLOW / WARN / ESCALATE / BLOCK)
 * with MCP tool classification, resource scoping, and content scanning.
 */

import { createHash } from "node:crypto";
import { RiskEngine, RiskLevel, riskOrd } from "./risk.js";
import { ScopeBoundary } from "./scope.js";
import { ContentScanner } from "./content.js";
import type { PolicyConfig } from "./policy.js";

export enum CheckVerdict {
  ALLOW = "allow",
  WARN = "warn",
  ESCALATE = "escalate",
  BLOCK = "block",
}

export interface ParamsSummary {
  resource_id_hash?: string;
  transaction_amount?: string;
  operation_scope?: "single" | "batch" | "export";
  mcp_server?: string;
  mcp_operation?: string;
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
  params_summary?: ParamsSummary;
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
    // CRUD
    "create", "update", "delete", "remove", "add", "set", "put",
    "post", "patch", "push", "insert", "move", "write", "fork",
    // Communication
    "send", "publish", "broadcast", "notify", "reply",
    // State changes
    "resolve", "approve", "reject", "assign", "merge",
    "submit", "cancel", "revoke", "grant",
    // Scheduling / activation
    "schedule", "queue", "enqueue", "activate", "launch",
    "enable", "disable",
    // Execution
    "start", "execute", "run", "dispense", "transfer",
    // IaC / DevOps
    "apply", "destroy", "scale", "rollout", "upgrade",
    "deploy", "provision", "terminate", "rollback", "revert", "sync",
    // Clinical / Healthcare
    "prescribe", "order", "administer", "discontinue", "titrate",
    // Supply chain / Finance
    "adjust", "reverse", "reopen", "reclassify", "divert", "route",
    // Marketing / Enrollment
    "enroll", "unsubscribe", "suppress", "export", "import", "configure",
  ].join("|") + ")(?:_|$)",
  "i",
);

function parseMcpTool(toolName: string): { server: string; operation: string } | null {
  const parts = toolName.split("__");
  if (parts.length < 3 || parts[0] !== "mcp") return null;
  return { server: parts.slice(1, -1).join("__"), operation: parts[parts.length - 1] };
}

/** Hash a resource ID for safe audit logging (no plaintext PII). */
function hashResourceId(id: string): string {
  return createHash("sha256").update(id).digest("hex").slice(0, 16);
}

/** Extract first *_id field from params for resource tracking. */
function extractResourceId(params: Record<string, unknown>): string | undefined {
  for (const [key, val] of Object.entries(params)) {
    if (/_id$|^id$/.test(key) && val != null && val !== "") return String(val);
  }
  return undefined;
}

/** Extract transaction amount from params. */
function extractAmount(params: Record<string, unknown>): string | undefined {
  for (const key of ["amount", "value", "total", "price", "cost"]) {
    const val = params[key];
    if (val != null && val !== "") return String(val);
  }
  return undefined;
}

/** Infer operation scope from operation name or params. */
function inferScope(operation: string, params: Record<string, unknown>): "single" | "batch" | "export" | undefined {
  if (/bulk|batch|mass|all\b/i.test(operation)) return "batch";
  if (/export|download|extract/i.test(operation)) return "export";
  if (Array.isArray(params.ids) || Array.isArray(params.items)) return "batch";
  return "single";
}

/** Build a ParamsSummary from MCP tool context. */
function buildParamsSummary(
  parsed: { server: string; operation: string } | null,
  params: Record<string, unknown>,
): ParamsSummary | undefined {
  if (!parsed) return undefined;
  const resourceId = extractResourceId(params);
  const amount = extractAmount(params);
  const scope = inferScope(parsed.operation, params);
  return {
    mcp_server: parsed.server,
    mcp_operation: parsed.operation,
    ...(resourceId && { resource_id_hash: hashResourceId(resourceId) }),
    ...(amount && { transaction_amount: amount }),
    ...(scope && { operation_scope: scope }),
  };
}

export class ScopeChecker {
  readonly boundary: ScopeBoundary;
  readonly riskEngine: RiskEngine;
  readonly scanner: ContentScanner;
  readonly policy: PolicyConfig;

  constructor(
    boundary: ScopeBoundary,
    riskEngine?: RiskEngine,
    scanner?: ContentScanner,
    policy?: PolicyConfig,
  ) {
    this.boundary = boundary;
    this.riskEngine = riskEngine ?? RiskEngine.default();
    this.scanner = scanner ?? new ContentScanner();
    this.policy = policy ?? {};
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

    if (this.isBoundaryUnavailable()) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target: extractTarget(toolName, params),
        reason:
          this.boundary.load_state === "invalid"
            ? "scope boundary config is invalid — fix .claude/scope-boundary.json before proceeding"
            : "scope boundary config is missing — create .claude/scope-boundary.json before proceeding",
        risk_level: RiskLevel.HIGH,
        scope_violation: true,
      };
    }

    if (this.policy.require_scope_boundary && this.boundary.isEmpty) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target: extractTarget(toolName, params),
        reason: "policy requires a non-empty scope boundary before any tool use",
        risk_level: RiskLevel.HIGH,
        scope_violation: true,
      };
    }

    if (this.isToolBlocked(toolName)) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target: extractTarget(toolName, params),
        reason: `policy blocks tool "${toolName}"`,
        risk_level: RiskLevel.HIGH,
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
        const risk = this.assessRisk(toolName, params);
        return this.riskOnlyResult(toolName, params, risk);
      }
      return this.checkFileTool(toolName, params);
    }

    // 5. Bash: check risk (scope boundary not needed).
    if (toolName === "Bash") {
      return this.checkBash(toolName, params);
    }

    // 7. Everything else: unknown tool — minimum WARN for safety.
    const risk = this.assessRisk(toolName, params);
    const effectiveRisk = riskOrd(risk) >= riskOrd(RiskLevel.MEDIUM) ? risk : RiskLevel.MEDIUM;
    return {
      verdict: verdictForRisk(effectiveRisk, this.maxRiskAutoAllow()),
      tool: toolName,
      target: extractTarget(toolName, params),
      reason: `unknown tool — elevated to ${effectiveRisk} risk for safety`,
      risk_level: effectiveRisk,
      scope_violation: false,
    };
  }

  private checkReadTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const target = extractTarget(toolName, params);
    const risk = this.assessRisk(toolName, params);
    const filePath = readFilePathFromParams(params);
    const url = extractUrlFromParams(params);

    if (filePath && !this.boundary.isEmpty && !this.boundary.isFileInScope(filePath)) {
      return {
        verdict: risk === RiskLevel.HIGH ? CheckVerdict.BLOCK : CheckVerdict.WARN,
        tool: toolName,
        target: filePath,
        reason: `out of scope (${filePath}) — update .claude/scope-boundary.json before reading it`,
        risk_level: risk,
        scope_violation: true,
      };
    }

    if (toolName === "WebFetch") {
      const urlAccess = this.boundary.getUrlAccess(url);
      if (urlAccess === "blocked") {
        return {
          verdict: CheckVerdict.BLOCK,
          tool: toolName,
          target,
          reason: "URL is outside the allowed boundary",
          risk_level: RiskLevel.HIGH,
          scope_violation: true,
        };
      }
      if (urlAccess === "unknown") {
        return {
          verdict: CheckVerdict.WARN,
          tool: toolName,
          target,
          reason: "URL boundary is configured, but this fetch call does not expose a verifiable URL",
          risk_level: RiskLevel.MEDIUM,
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
    const scan = this.scanner.scan(JSON.stringify(params));
    const effectiveRisk = riskOrd(scan.highest_risk) > riskOrd(risk) ? scan.highest_risk : risk;
    if (effectiveRisk !== RiskLevel.LOW) {
      return {
        verdict: verdictForRisk(effectiveRisk, this.maxRiskAutoAllow()),
        tool: toolName,
        target,
        reason:
          scan.flags.length > 0
            ? `read tool matched sensitive content: ${scan.flags.map(f => f.pattern_name).join(", ")}`
            : `${effectiveRisk} risk read`,
        risk_level: effectiveRisk,
        scope_violation: false,
        content_flags: scan.flags.map(f => f.pattern_name),
      };
    }

    return {
      verdict: CheckVerdict.ALLOW,
      tool: toolName,
      target,
      reason: "read-only tool",
      risk_level: RiskLevel.LOW,
      scope_violation: false,
    };
  }

  private checkMcpTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const parsed = parseMcpTool(toolName);
    const target = extractTarget(toolName, params);
    const risk = this.assessRisk(toolName, params);
    const matchedRules = this.riskEngine.matchingRules(toolName, params).map(r => r.name);
    const params_summary = buildParamsSummary(parsed, params);
    const resourceCandidates = extractResourceCandidates(parsed, params);
    const url = extractUrlFromParams(params);

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
        params_summary,
      };
    }

    // 1b. OrgBoundary: per-server operation rules
    if (parsed && !this.boundary.isMcpOperationAllowed(parsed.server, parsed.operation)) {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target,
        reason: `MCP operation "${parsed.operation}" not allowed on server "${parsed.server}" — configure mcp_resource_rules`,
        risk_level: RiskLevel.HIGH,
        scope_violation: true,
        matched_rules: matchedRules,
        params_summary,
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
        params_summary,
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
        params_summary,
      };
    }

    // 4. Content scan on params
    const scan = this.scanner.scan(paramsStr);
    const contentFlags = scan.flags.length > 0 ? scan.flags.map(f => f.pattern_name) : undefined;

    if (url) {
      const urlAccess = this.boundary.getUrlAccess(url);
      if (urlAccess === "blocked") {
        return {
          verdict: CheckVerdict.BLOCK,
          tool: toolName,
          target,
          reason: "URL is outside the allowed boundary",
          risk_level: RiskLevel.HIGH,
          scope_violation: true,
          matched_rules: matchedRules,
          params_summary,
        };
      }
    }

    // 5. Resource scope check for write operations
    const isWrite = parsed ? MCP_WRITE_VERBS.test(parsed.operation) : false;
    const resourceAccess = this.boundary.getResourceAccess(resourceCandidates);

    if (resourceAccess === "protected" || resourceAccess === "blocked") {
      return {
        verdict: CheckVerdict.BLOCK,
        tool: toolName,
        target,
        reason:
          resourceAccess === "protected"
            ? "protected resource — MCP access denied"
            : "blocked resource — MCP access denied",
        risk_level: RiskLevel.HIGH,
        scope_violation: true,
        matched_rules: matchedRules,
        params_summary,
      };
    }

    if (resourceAccess === "unknown" && this.boundary.hasResourceRules) {
      return {
        verdict: isWrite ? CheckVerdict.BLOCK : CheckVerdict.WARN,
        tool: toolName,
        target,
        reason:
          "resource scope is configured, but this MCP call does not expose a verifiable resource identifier",
        risk_level: isWrite ? RiskLevel.HIGH : RiskLevel.MEDIUM,
        scope_violation: true,
        matched_rules: matchedRules,
        params_summary,
      };
    }

    if (isWrite) {
      // Write operations: minimum MEDIUM, risk rules can escalate further
      const effectiveRisk = riskOrd(risk) > riskOrd(RiskLevel.MEDIUM) ? risk : RiskLevel.MEDIUM;
      const policyVerdict = verdictForRisk(effectiveRisk, this.maxRiskAutoAllow());
      const verdict = policyVerdict === CheckVerdict.ALLOW ? CheckVerdict.WARN : policyVerdict;
      return {
        verdict,
        tool: toolName,
        target,
        reason: `MCP write operation "${parsed?.operation}" — ${effectiveRisk} risk`,
        risk_level: effectiveRisk,
        scope_violation: false,
        matched_rules: matchedRules,
        content_flags: contentFlags,
        params_summary,
      };
    }

    // 6. Read operation — still run risk assessment on params
    if (risk !== RiskLevel.LOW) {
      return {
        verdict: verdictForRisk(risk, this.maxRiskAutoAllow()),
        tool: toolName,
        target,
        reason: `MCP read but ${risk} risk detected in params`,
        risk_level: risk,
        scope_violation: false,
        matched_rules: matchedRules,
        content_flags: contentFlags,
        params_summary,
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
      params_summary,
    };
  }

  private checkFileTool(toolName: string, params: Record<string, unknown>): CheckResult {
    const filePath = (params.file_path ?? params.notebook_path ?? "") as string;
    const risk = this.assessRisk(toolName, params);

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
      const verdict = verdictForRisk(risk, this.maxRiskAutoAllow());
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
    const risk = this.assessRisk(toolName, params);
    const matchedRules = this.riskEngine.matchingRules(toolName, params).map(r => r.name);

    const verdict = verdictForRisk(risk, this.maxRiskAutoAllow());
    if (verdict !== CheckVerdict.ALLOW) {
      return {
        verdict,
        tool: toolName,
        target: command,
        reason:
          risk === RiskLevel.HIGH
            ? "high-risk shell command — requires explicit user confirmation to proceed"
            : "medium-risk shell command",
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
      verdict: verdictForRisk(risk, this.maxRiskAutoAllow()),
      tool: toolName,
      target: extractTarget(toolName, params),
      reason: `${risk} risk`,
      risk_level: risk,
      scope_violation: false,
    };
  }

  private assessRisk(toolName: string, params: Record<string, unknown>): RiskLevel {
    const risk = this.riskEngine.assess(toolName, params);
    const override = getToolOverride(this.policy, toolName);
    if (override && riskOrd(override) > riskOrd(risk)) return override;
    return risk;
  }

  private maxRiskAutoAllow(): RiskLevel {
    return this.policy.max_risk_auto_allow ?? RiskLevel.LOW;
  }

  private isBoundaryUnavailable(): boolean {
    return this.boundary.load_state === "missing" || this.boundary.load_state === "invalid";
  }

  private isToolBlocked(toolName: string): boolean {
    return (this.policy.blocked_tools ?? []).some(
      (blocked) => blocked.toLowerCase() === toolName.toLowerCase(),
    );
  }
}

function verdictForRisk(
  risk: RiskLevel,
  maxRiskAutoAllow: RiskLevel = RiskLevel.LOW,
): CheckVerdict {
  if (riskOrd(risk) <= riskOrd(maxRiskAutoAllow)) return CheckVerdict.ALLOW;
  if (risk === RiskLevel.HIGH) return CheckVerdict.BLOCK;
  if (risk === RiskLevel.MEDIUM) return CheckVerdict.WARN;
  return CheckVerdict.ALLOW;
}

function extractTarget(toolName: string, params: Record<string, unknown>): string {
  for (const key of [
    "file_path",
    "notebook_path",
    "path",
    "command",
    "pattern",
    "url",
    "uri",
    "endpoint",
    "link",
    "href",
    "query",
    "sql",
    "resource",
    "resource_id",
  ]) {
    const val = params[key];
    if (val != null && val !== "") return String(val).slice(0, 500);
  }
  const resourceId = extractResourceId(params);
  if (resourceId) return resourceId.slice(0, 500);
  return "";
}

function readFilePathFromParams(params: Record<string, unknown>): string {
  return String(params.file_path ?? params.notebook_path ?? params.path ?? "");
}

function extractUrlFromParams(params: Record<string, unknown>): string | undefined {
  for (const key of ["url", "uri", "endpoint", "link", "href"]) {
    const value = params[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return undefined;
}

function getToolOverride(policy: PolicyConfig, toolName: string): RiskLevel | undefined {
  const match = Object.entries(policy.tool_overrides ?? {}).find(
    ([tool]) => tool.toLowerCase() === toolName.toLowerCase(),
  );
  return match?.[1];
}

function extractResourceCandidates(
  parsed: { server: string; operation: string } | null,
  params: Record<string, unknown>,
): string[] {
  const candidates = new Set<string>();
  const target = extractTarget("", params);
  if (target) candidates.add(target);
  if (!parsed) return Array.from(candidates);

  const explicitResource = params.resource;
  if (typeof explicitResource === "string" && explicitResource !== "") {
    candidates.add(explicitResource);
    if (!explicitResource.includes(":")) {
      candidates.add(`${parsed.server}:${explicitResource}`);
    }
  }

  for (const [key, value] of Object.entries(params)) {
    if (value == null || value === "" || !/_id$|^id$/.test(key)) continue;
    const id = String(value);
    const base = key === "id" ? "record" : key.replace(/_id$/, "");
    candidates.add(`${parsed.server}:${base}:${id}`);
    candidates.add(`${parsed.server}:${base}s:${id}`);
    candidates.add(`${parsed.server}:${id}`);
  }

  return Array.from(candidates);
}
