/**
 * Policy engine — layered configuration with compliance presets.
 *
 * Supports:
 *   - compliance_mode: "hipaa" | "sox" | "pci" | "legal" | "custom"
 *   - extends: chain up to 5 levels of policy inheritance
 *   - tool_overrides: per-tool risk level overrides
 *   - most-restrictive-wins merge semantics
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { RiskLevel, RiskRule, RiskEngine, builtinRules, riskOrd } from "./risk.js";

export type ComplianceMode = "hipaa" | "sox" | "pci" | "legal" | "custom";

export interface PolicyConfig {
  compliance_mode?: ComplianceMode;
  extends?: string;
  tool_overrides?: Record<string, RiskLevel>;
  extra_rules?: Array<{
    name: string;
    tool: string;
    pattern: string;
    risk: RiskLevel;
    description?: string;
  }>;
  blocked_tools?: string[];
  max_risk_auto_allow?: RiskLevel;
  require_scope_boundary?: boolean;
}

export interface ValidateResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const MAX_EXTENDS_DEPTH = 5;

/** Built-in compliance presets. */
const PRESETS: Record<ComplianceMode, Partial<PolicyConfig>> = {
  hipaa: {
    tool_overrides: {
      "WebFetch": RiskLevel.MEDIUM,
      "WebSearch": RiskLevel.MEDIUM,
    },
    extra_rules: [
      { name: "hipaa_phi_export", tool: "*", pattern: "(?:^|[^a-zA-Z])(export|download|extract).*(?:patient|medical|health|PHI)", risk: RiskLevel.HIGH, description: "PHI data export" },
      { name: "hipaa_external_send", tool: "*", pattern: "(?:^|[^a-zA-Z])(send|email|fax|transmit).*(?:patient|medical|record)", risk: RiskLevel.HIGH, description: "External PHI transmission" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  sox: {
    tool_overrides: {
      "Write": RiskLevel.HIGH,
    },
    extra_rules: [
      { name: "sox_financial_mutation", tool: "*", pattern: "(?:^|[^a-zA-Z])(journal|ledger|accrual|revenue|depreciation).*(?:adjust|modify|override|reverse)", risk: RiskLevel.HIGH, description: "Financial record mutation" },
      { name: "sox_audit_trail", tool: "*", pattern: "(?:^|[^a-zA-Z])(delete|truncate|purge).*(?:audit|log|trail|history)", risk: RiskLevel.HIGH, description: "Audit trail deletion" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  pci: {
    tool_overrides: {},
    extra_rules: [
      { name: "pci_card_data", tool: "*", pattern: "(?:^|[^a-zA-Z])(card_?number|cvv|expir|pan|track_?data|mag_?stripe)", risk: RiskLevel.HIGH, description: "Payment card data access" },
      { name: "pci_key_material", tool: "*", pattern: "(?:^|[^a-zA-Z])(encryption_key|dek|kek|hsm|key_?block)", risk: RiskLevel.HIGH, description: "Cryptographic key material" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  legal: {
    tool_overrides: {
      "WebFetch": RiskLevel.MEDIUM,
    },
    extra_rules: [
      { name: "legal_privilege", tool: "*", pattern: "(?:^|[^a-zA-Z])(attorney.client|privileged|work.product|litigation.hold)", risk: RiskLevel.HIGH, description: "Privileged legal content" },
      { name: "legal_external_comms", tool: "*", pattern: "(?:^|[^a-zA-Z])(send|post|publish|broadcast).*(?:opposing|counsel|court|regulator)", risk: RiskLevel.HIGH, description: "External legal communications" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  custom: {
    // No preset rules — fully user-defined
  },
};

/** Load a policy file, resolving extends chain. */
export function loadPolicy(policyPath: string, depth = 0): PolicyConfig {
  if (depth > MAX_EXTENDS_DEPTH) {
    throw new Error(`policy extends chain exceeds max depth of ${MAX_EXTENDS_DEPTH}`);
  }
  if (!existsSync(policyPath)) {
    return {};
  }
  const raw = JSON.parse(readFileSync(policyPath, "utf-8")) as PolicyConfig;

  // Resolve extends
  if (raw.extends) {
    const basePath = resolve(dirname(policyPath), raw.extends);
    const base = loadPolicy(basePath, depth + 1);
    return mergePolicies(base, raw);
  }

  // Apply compliance preset as base
  if (raw.compliance_mode && raw.compliance_mode !== "custom") {
    const preset = PRESETS[raw.compliance_mode];
    if (preset) {
      return mergePolicies(preset as PolicyConfig, raw);
    }
  }

  return raw;
}

/** Merge two policies with most-restrictive-wins semantics. */
function mergePolicies(base: PolicyConfig, overlay: PolicyConfig): PolicyConfig {
  const merged: PolicyConfig = { ...base };

  // compliance_mode: overlay wins
  if (overlay.compliance_mode) merged.compliance_mode = overlay.compliance_mode;

  // tool_overrides: most restrictive wins per tool
  if (base.tool_overrides || overlay.tool_overrides) {
    merged.tool_overrides = { ...base.tool_overrides };
    for (const [tool, risk] of Object.entries(overlay.tool_overrides ?? {})) {
      const existing = merged.tool_overrides![tool];
      if (!existing || riskOrd(risk) > riskOrd(existing)) {
        merged.tool_overrides![tool] = risk;
      }
    }
  }

  // extra_rules: union (dedupe by name)
  if (base.extra_rules || overlay.extra_rules) {
    type ExtraRule = NonNullable<PolicyConfig["extra_rules"]>[number];
    const byName = new Map<string, ExtraRule>();
    for (const r of base.extra_rules ?? []) byName.set(r.name, r);
    for (const r of overlay.extra_rules ?? []) byName.set(r.name, r);
    merged.extra_rules = Array.from(byName.values());
  }

  // blocked_tools: union
  if (base.blocked_tools || overlay.blocked_tools) {
    merged.blocked_tools = [...new Set([...(base.blocked_tools ?? []), ...(overlay.blocked_tools ?? [])])];
  }

  // max_risk_auto_allow: most restrictive (lower)
  if (base.max_risk_auto_allow || overlay.max_risk_auto_allow) {
    const a = base.max_risk_auto_allow ?? RiskLevel.MEDIUM;
    const b = overlay.max_risk_auto_allow ?? RiskLevel.MEDIUM;
    merged.max_risk_auto_allow = riskOrd(a) <= riskOrd(b) ? a : b;
  }

  // require_scope_boundary: true if either is true
  if (base.require_scope_boundary || overlay.require_scope_boundary) {
    merged.require_scope_boundary = true;
  }

  return merged;
}

/** Build a RiskEngine from a PolicyConfig (builtin rules + extra + overrides). */
export function buildRiskEngine(config: PolicyConfig): RiskEngine {
  const rules: RiskRule[] = [...builtinRules()];

  // Add extra rules from policy
  if (config.extra_rules) {
    for (const r of config.extra_rules) {
      rules.push(new RiskRule({
        name: r.name,
        tool: r.tool,
        pattern: r.pattern,
        risk: r.risk,
        description: r.description,
      }));
    }
  }

  return new RiskEngine(rules);
}

/** Validate a policy config for common errors. */
export function validatePolicy(config: PolicyConfig): ValidateResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (config.compliance_mode && !PRESETS[config.compliance_mode]) {
    errors.push(`unknown compliance_mode: "${config.compliance_mode}"`);
  }

  if (config.extra_rules) {
    for (const r of config.extra_rules) {
      if (!r.name) errors.push("extra_rules entry missing name");
      if (!r.tool) errors.push(`extra_rules "${r.name}" missing tool`);
      if (!r.pattern) errors.push(`extra_rules "${r.name}" missing pattern`);
      try {
        new RegExp(r.pattern, "i");
      } catch {
        errors.push(`extra_rules "${r.name}" has invalid regex: ${r.pattern}`);
      }
      if (!["low", "medium", "high"].includes(r.risk)) {
        errors.push(`extra_rules "${r.name}" has invalid risk: ${r.risk}`);
      }
    }
  }

  if (config.tool_overrides) {
    for (const [tool, risk] of Object.entries(config.tool_overrides)) {
      if (!["low", "medium", "high"].includes(risk)) {
        errors.push(`tool_overrides "${tool}" has invalid risk: ${risk}`);
      }
    }
  }

  if (config.blocked_tools?.length && config.blocked_tools.some(t => !t)) {
    warnings.push("blocked_tools contains empty strings");
  }

  return { valid: errors.length === 0, errors, warnings };
}
