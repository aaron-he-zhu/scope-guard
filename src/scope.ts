/**
 * Scope boundary: the core data structure that defines what an agent is allowed to do.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, normalize, dirname, isAbsolute } from "node:path";
import { RiskLevel } from "./risk.js";

export interface Assumption {
  text: string;
  verified: boolean;
  verification_method?: string;
}

export interface ScopeRevision {
  action: string;
  timestamp: string;
  reason: string;
  added_files: string[];
  added_dirs: string[];
}

/** Resource-level scoping for API/SaaS tools */
export interface ResourceScope {
  allowed_resources?: string[];
  blocked_resources?: string[];
  protected_resources?: string[];
  allowed_urls?: string[];
  blocked_urls?: string[];
  escalation_keywords?: string[];
  blocked_keywords?: string[];
}

/** Per-server operation-level access control */
export interface McpResourceRule {
  server: string;
  allowed_operations?: string[];
  blocked_operations?: string[];
}

/** Organizational boundary for multi-tenant */
export interface OrgBoundary {
  tenant_id?: string;
  allowed_mcp_servers?: string[];
  blocked_mcp_servers?: string[];
  mcp_resource_rules?: McpResourceRule[];
}

export interface ScopeBoundaryData {
  files_in_scope: string[];
  dirs_in_scope: string[];
  assumptions: Assumption[];
  risk_level: string;
  approval_required: boolean;
  task_summary: string;
  created_at: string;
  revisions: ScopeRevision[];
  resources?: ResourceScope;
  org_boundary?: OrgBoundary;
  expand_requires_reason?: boolean;
}

export type ScopeBoundaryLoadState = "explicit" | "loaded" | "missing" | "invalid";

type ResourceMatchStatus =
  | "allowed"
  | "protected"
  | "explicit_blocked"
  | "implicit_blocked"
  | "default_allowed";

/** Escape special regex characters. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function wildcardMatch(pattern: string, value: string): boolean {
  const re = new RegExp("^" + escapeRegex(pattern).replace(/\\\*/g, ".*") + "$", "i");
  return re.test(value);
}

/**
 * Word-boundary keyword matching.
 * Uses non-letter boundaries for ASCII keywords; falls back to substring for CJK.
 */
function keywordBoundaryMatch(keyword: string, text: string): boolean {
  // CJK detection: if keyword contains CJK characters, use substring match
  if (/[\u3000-\u9fff\uac00-\ud7af\uff00-\uffef]/.test(keyword)) {
    return text.toLowerCase().includes(keyword.toLowerCase());
  }
  const escaped = escapeRegex(keyword);
  const re = new RegExp(`(?:^|[^a-zA-Z0-9])${escaped}(?:$|[^a-zA-Z0-9])`, "i");
  return re.test(text);
}

/**
 * Glob-style server name matching.
 * Supports `*` wildcards: "notion" matches exactly, "notion_*" matches "notion_prod".
 * Falls back to exact match when no wildcards present.
 */
function serverGlobMatch(pattern: string, server: string): boolean {
  const p = pattern.toLowerCase();
  const s = server.toLowerCase();
  if (!p.includes("*")) return p === s;
  const re = new RegExp("^" + escapeRegex(p).replace(/\\\*/g, ".*") + "$");
  return re.test(s);
}

function globSegmentMatch(pattern: string, value: string): boolean {
  const pParts = pattern.split(":");
  const vParts = value.split(":");
  let pi = 0, vi = 0;
  while (pi < pParts.length && vi < vParts.length) {
    if (pParts[pi] === "**") return true;
    if (pParts[pi] === "*" || pParts[pi].toLowerCase() === vParts[vi].toLowerCase()) { pi++; vi++; continue; }
    // Support simple wildcards within segments: "get_*" matches "get_deal"
    const re = new RegExp("^" + pParts[pi].replace(/\*/g, ".*") + "$", "i");
    if (re.test(vParts[vi])) { pi++; vi++; continue; }
    return false;
  }
  return pi === pParts.length && vi === vParts.length;
}

function validateScopeBoundaryData(raw: unknown): {
  valid: boolean;
  data?: Partial<ScopeBoundaryData>;
  error?: string;
} {
  if (!isPlainObject(raw)) {
    return { valid: false, error: "scope boundary must be a JSON object" };
  }

  const stringArrayFields = ["files_in_scope", "dirs_in_scope"] as const;
  for (const field of stringArrayFields) {
    const value = raw[field];
    if (value !== undefined && !isStringArray(value)) {
      return { valid: false, error: `${field} must be an array of strings` };
    }
  }

  if (raw.assumptions !== undefined && !Array.isArray(raw.assumptions)) {
    return { valid: false, error: "assumptions must be an array" };
  }

  if (raw.revisions !== undefined && !Array.isArray(raw.revisions)) {
    return { valid: false, error: "revisions must be an array" };
  }

  if (raw.risk_level !== undefined && typeof raw.risk_level !== "string") {
    return { valid: false, error: "risk_level must be a string" };
  }

  if (raw.approval_required !== undefined && typeof raw.approval_required !== "boolean") {
    return { valid: false, error: "approval_required must be a boolean" };
  }

  if (raw.task_summary !== undefined && typeof raw.task_summary !== "string") {
    return { valid: false, error: "task_summary must be a string" };
  }

  if (raw.created_at !== undefined && typeof raw.created_at !== "string") {
    return { valid: false, error: "created_at must be a string" };
  }

  if (raw.expand_requires_reason !== undefined && typeof raw.expand_requires_reason !== "boolean") {
    return { valid: false, error: "expand_requires_reason must be a boolean" };
  }

  if (raw.resources !== undefined) {
    if (!isPlainObject(raw.resources)) {
      return { valid: false, error: "resources must be a JSON object" };
    }
    for (const field of [
      "allowed_resources",
      "blocked_resources",
      "protected_resources",
      "allowed_urls",
      "blocked_urls",
      "escalation_keywords",
      "blocked_keywords",
    ] as const) {
      const value = raw.resources[field];
      if (value !== undefined && !isStringArray(value)) {
        return { valid: false, error: `resources.${field} must be an array of strings` };
      }
    }
  }

  if (raw.org_boundary !== undefined) {
    if (!isPlainObject(raw.org_boundary)) {
      return { valid: false, error: "org_boundary must be a JSON object" };
    }
    for (const field of ["allowed_mcp_servers", "blocked_mcp_servers"] as const) {
      const value = raw.org_boundary[field];
      if (value !== undefined && !isStringArray(value)) {
        return { valid: false, error: `org_boundary.${field} must be an array of strings` };
      }
    }
    const rules = raw.org_boundary.mcp_resource_rules;
    if (rules !== undefined) {
      if (!Array.isArray(rules)) {
        return { valid: false, error: "org_boundary.mcp_resource_rules must be an array" };
      }
      for (const [index, rule] of rules.entries()) {
        if (!isPlainObject(rule) || typeof rule.server !== "string") {
          return { valid: false, error: `org_boundary.mcp_resource_rules[${index}] must include a string server` };
        }
        if (rule.allowed_operations !== undefined && !isStringArray(rule.allowed_operations)) {
          return { valid: false, error: `org_boundary.mcp_resource_rules[${index}].allowed_operations must be an array of strings` };
        }
        if (rule.blocked_operations !== undefined && !isStringArray(rule.blocked_operations)) {
          return { valid: false, error: `org_boundary.mcp_resource_rules[${index}].blocked_operations must be an array of strings` };
        }
      }
    }
  }

  return { valid: true, data: raw as Partial<ScopeBoundaryData> };
}

export class ScopeBoundary {
  files_in_scope: string[];
  dirs_in_scope: string[];
  assumptions: Assumption[];
  risk_level: RiskLevel;
  approval_required: boolean;
  task_summary: string;
  created_at: string;
  revisions: ScopeRevision[];
  resources?: ResourceScope;
  org_boundary?: OrgBoundary;
  expand_requires_reason?: boolean;
  readonly load_state: ScopeBoundaryLoadState;
  readonly load_error?: string;

  constructor(
    data?: Partial<ScopeBoundaryData>,
    meta?: { load_state?: ScopeBoundaryLoadState; load_error?: string },
  ) {
    this.files_in_scope = data?.files_in_scope ?? [];
    this.dirs_in_scope = data?.dirs_in_scope ?? [];
    this.assumptions = data?.assumptions ?? [];
    const rl = data?.risk_level;
    this.risk_level =
      rl === RiskLevel.LOW || rl === RiskLevel.MEDIUM || rl === RiskLevel.HIGH
        ? rl
        : RiskLevel.LOW;
    this.approval_required = data?.approval_required ?? false;
    this.task_summary = data?.task_summary ?? "";
    this.created_at = data?.created_at ?? new Date().toISOString();
    this.revisions = data?.revisions ?? [];
    this.resources = data?.resources;
    this.org_boundary = data?.org_boundary;
    this.expand_requires_reason = data?.expand_requires_reason;
    this.load_state = meta?.load_state ?? "explicit";
    this.load_error = meta?.load_error;
  }

  get isEmpty(): boolean {
    return this.files_in_scope.length === 0 && this.dirs_in_scope.length === 0;
  }

  get hasOrgBoundary(): boolean {
    const org = this.org_boundary;
    return !!(org?.allowed_mcp_servers?.length || org?.blocked_mcp_servers?.length);
  }

  get hasResourceRules(): boolean {
    const res = this.resources;
    return !!(
      res?.allowed_resources?.length ||
      res?.blocked_resources?.length ||
      res?.protected_resources?.length
    );
  }

  get hasUrlRules(): boolean {
    const res = this.resources;
    return !!(res?.allowed_urls?.length || res?.blocked_urls?.length);
  }

  /** Check if a file path falls within the declared scope. */
  isFileInScope(filePath: string): boolean {
    const normalised = normalisePath(filePath);

    for (const f of this.files_in_scope) {
      if (normalisePath(f) === normalised) return true;
    }

    for (const d of this.dirs_in_scope) {
      let nd = normalisePath(d);
      if (!nd.endsWith("/")) nd += "/";
      if (normalised.startsWith(nd)) return true;
    }

    return false;
  }

  isMcpServerAllowed(server: string): boolean {
    const org = this.org_boundary;
    if (!org) return true;
    if (org.blocked_mcp_servers?.some(b => serverGlobMatch(b, server))) return false;
    if (org.allowed_mcp_servers && org.allowed_mcp_servers.length > 0) {
      return org.allowed_mcp_servers.some(a => serverGlobMatch(a, server));
    }
    return true;
  }

  /**
   * Check if a specific MCP operation is allowed on a server.
   * Uses mcp_resource_rules for per-server operation allow/block.
   * Returns true if no rules apply or operation is allowed.
   */
  isMcpOperationAllowed(server: string, operation: string): boolean {
    const rules = this.org_boundary?.mcp_resource_rules;
    if (!rules || rules.length === 0) return true;
    for (const rule of rules) {
      if (!serverGlobMatch(rule.server, server)) continue;
      if (rule.blocked_operations?.some(p => serverGlobMatch(p, operation))) return false;
      if (rule.allowed_operations && rule.allowed_operations.length > 0) {
        return rule.allowed_operations.some(p => serverGlobMatch(p, operation));
      }
    }
    return true;
  }

  private resourceMatchStatus(resource: string): ResourceMatchStatus {
    const res = this.resources;
    if (!res) return "default_allowed";
    if (res.protected_resources?.some(p => globSegmentMatch(p, resource))) return "protected";
    if (res.blocked_resources?.some(p => globSegmentMatch(p, resource))) return "explicit_blocked";
    if (res.allowed_resources && res.allowed_resources.length > 0) {
      return res.allowed_resources.some(p => globSegmentMatch(p, resource))
        ? "allowed"
        : "implicit_blocked";
    }
    return "default_allowed";
  }

  isResourceAllowed(resource: string): "allowed" | "blocked" | "protected" {
    const status = this.resourceMatchStatus(resource);
    if (status === "protected") return "protected";
    if (status === "explicit_blocked" || status === "implicit_blocked") return "blocked";
    return "allowed";
  }

  isUrlAllowed(url: string): "allowed" | "blocked" {
    const res = this.resources;
    if (!res) return "allowed";
    if (res.blocked_urls?.some((pattern) => wildcardMatch(pattern, url))) return "blocked";
    if (res.allowed_urls && res.allowed_urls.length > 0) {
      return res.allowed_urls.some((pattern) => wildcardMatch(pattern, url)) ? "allowed" : "blocked";
    }
    return "allowed";
  }

  getUrlAccess(url?: string): "allowed" | "blocked" | "unknown" {
    if (!url) return this.hasUrlRules ? "unknown" : "allowed";
    return this.isUrlAllowed(url);
  }

  getResourceAccess(resources: string[]): "allowed" | "blocked" | "protected" | "unknown" {
    if (resources.length === 0) {
      return this.hasResourceRules ? "unknown" : "allowed";
    }

    let sawAllowed = false;
    let sawImplicitBlocked = false;
    for (const resource of resources) {
      const status = this.resourceMatchStatus(resource);
      if (status === "protected") return "protected";
      if (status === "explicit_blocked") return "blocked";
      if (status === "allowed" || status === "default_allowed") sawAllowed = true;
      if (status === "implicit_blocked") sawImplicitBlocked = true;
    }

    if (sawImplicitBlocked) return "blocked";
    if (sawAllowed) return "allowed";
    return "unknown";
  }

  matchEscalationKeywords(text: string): string[] {
    return (this.resources?.escalation_keywords ?? []).filter(k =>
      keywordBoundaryMatch(k, text)
    );
  }

  matchBlockedKeywords(text: string): string[] {
    return (this.resources?.blocked_keywords ?? []).filter(k =>
      keywordBoundaryMatch(k, text)
    );
  }

  /** Expand the scope boundary and record the revision. */
  expandScope(
    files?: string[],
    dirs?: string[],
    reason = "",
  ): void {
    if (this.expand_requires_reason && !reason.trim()) {
      throw new Error("expand_requires_reason is set — a non-empty reason is required");
    }

    const revision: ScopeRevision = {
      action: "expand",
      timestamp: new Date().toISOString(),
      reason,
      added_files: files ?? [],
      added_dirs: dirs ?? [],
    };

    const existingFiles = new Set(this.files_in_scope.map(normalisePath));
    for (const f of files ?? []) {
      if (!existingFiles.has(normalisePath(f))) {
        this.files_in_scope.push(f);
        existingFiles.add(normalisePath(f));
      }
    }

    const existingDirs = new Set(this.dirs_in_scope.map(normalisePath));
    for (const d of dirs ?? []) {
      if (!existingDirs.has(normalisePath(d))) {
        this.dirs_in_scope.push(d);
        existingDirs.add(normalisePath(d));
      }
    }

    this.revisions.push(revision);
  }

  toDict(): ScopeBoundaryData {
    return {
      files_in_scope: this.files_in_scope,
      dirs_in_scope: this.dirs_in_scope,
      assumptions: this.assumptions,
      risk_level: this.risk_level,
      approval_required: this.approval_required,
      task_summary: this.task_summary,
      created_at: this.created_at,
      revisions: this.revisions,
      resources: this.resources,
      org_boundary: this.org_boundary,
      expand_requires_reason: this.expand_requires_reason,
    };
  }

  save(path: string): void {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(this.toDict(), null, 2) + "\n");
  }

  static load(path: string): ScopeBoundary {
    if (!existsSync(path)) {
      return new ScopeBoundary(undefined, { load_state: "missing" });
    }
    try {
      const parsed = JSON.parse(readFileSync(path, "utf-8"));
      const validated = validateScopeBoundaryData(parsed);
      if (!validated.valid) {
        return new ScopeBoundary(undefined, {
          load_state: "invalid",
          load_error: validated.error ?? `invalid scope boundary in ${path}`,
        });
      }
      return new ScopeBoundary(validated.data, { load_state: "loaded" });
    } catch {
      return new ScopeBoundary(undefined, {
        load_state: "invalid",
        load_error: `failed to parse ${path}`,
      });
    }
  }
}

/**
 * Normalise a file path for comparison.
 * Always produces a forward-slash relative path so that scope boundaries
 * declared with relative paths cannot be bypassed using absolute paths,
 * backslash paths, or URL-encoded segments.
 */
export function normalisePath(p: string): string {
  // Normalise backslashes to forward slashes (prevents Windows bypass)
  const cleaned = p.trim().replace(/\\/g, "/").replace(/\/+$/, "");
  // Strip leading slash to force relative comparison
  const relative = cleaned.replace(/^\/+/, "");
  const normalised = normalize(relative);
  // Block path traversal — if result escapes root it's suspicious
  if (normalised.startsWith("..") || normalised.includes("/../")) return "__blocked__";
  return normalised;
}
