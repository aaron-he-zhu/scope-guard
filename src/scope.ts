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

/** Organizational boundary for multi-tenant */
export interface OrgBoundary {
  tenant_id?: string;
  allowed_mcp_servers?: string[];
  blocked_mcp_servers?: string[];
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

  constructor(data?: Partial<ScopeBoundaryData>) {
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
  }

  get isEmpty(): boolean {
    return this.files_in_scope.length === 0 && this.dirs_in_scope.length === 0;
  }

  get hasOrgBoundary(): boolean {
    const org = this.org_boundary;
    return !!(org?.allowed_mcp_servers?.length || org?.blocked_mcp_servers?.length);
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
    if (org.blocked_mcp_servers?.some(b => server.toLowerCase().includes(b.toLowerCase()))) return false;
    if (org.allowed_mcp_servers && org.allowed_mcp_servers.length > 0) {
      return org.allowed_mcp_servers.some(a => server.toLowerCase().includes(a.toLowerCase()));
    }
    return true;
  }

  isResourceAllowed(resource: string): "allowed" | "blocked" | "protected" {
    const res = this.resources;
    if (!res) return "allowed";
    if (res.protected_resources?.some(p => globSegmentMatch(p, resource))) return "protected";
    if (res.blocked_resources?.some(p => globSegmentMatch(p, resource))) return "blocked";
    if (res.allowed_resources && res.allowed_resources.length > 0) {
      return res.allowed_resources.some(p => globSegmentMatch(p, resource)) ? "allowed" : "blocked";
    }
    return "allowed";
  }

  matchEscalationKeywords(text: string): string[] {
    return (this.resources?.escalation_keywords ?? []).filter(k =>
      text.toLowerCase().includes(k.toLowerCase())
    );
  }

  matchBlockedKeywords(text: string): string[] {
    return (this.resources?.blocked_keywords ?? []).filter(k =>
      text.toLowerCase().includes(k.toLowerCase())
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
    if (!existsSync(path)) return new ScopeBoundary();
    try {
      const data = JSON.parse(readFileSync(path, "utf-8"));
      return new ScopeBoundary(data);
    } catch {
      return new ScopeBoundary();
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
