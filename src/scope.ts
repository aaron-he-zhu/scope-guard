/**
 * Scope boundary: the core data structure that defines what an agent is allowed to do.
 * TypeScript port of src/preflight/scope.py
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

export interface ScopeBoundaryData {
  files_in_scope: string[];
  dirs_in_scope: string[];
  assumptions: Assumption[];
  risk_level: string;
  approval_required: boolean;
  task_summary: string;
  created_at: string;
  revisions: ScopeRevision[];
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

  constructor(data?: Partial<ScopeBoundaryData>) {
    this.files_in_scope = data?.files_in_scope ?? [];
    this.dirs_in_scope = data?.dirs_in_scope ?? [];
    this.assumptions = data?.assumptions ?? [];
    this.risk_level = (data?.risk_level as RiskLevel) ?? RiskLevel.LOW;
    this.approval_required = data?.approval_required ?? false;
    this.task_summary = data?.task_summary ?? "";
    this.created_at = data?.created_at ?? new Date().toISOString();
    this.revisions = data?.revisions ?? [];
  }

  get isEmpty(): boolean {
    return this.files_in_scope.length === 0 && this.dirs_in_scope.length === 0;
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

  /** Expand the scope boundary and record the revision. */
  expandScope(
    files?: string[],
    dirs?: string[],
    reason = "",
  ): void {
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
 * Uses normalize() to collapse '..' and '.' segments, preventing traversal bypasses.
 */
export function normalisePath(p: string): string {
  const cleaned = p.trim().replace(/\/+$/, "");
  if (isAbsolute(cleaned)) return resolve(cleaned);
  return normalize(cleaned);
}
