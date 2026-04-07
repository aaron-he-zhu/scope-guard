/**
 * Policy engine — layered configuration with compliance presets.
 *
 * Supports:
 *   - compliance_mode: "hipaa" | "sox" | "pci" | "legal" | "hr" | "clinical" | "research" | "supply_chain" | "supply_chain_sap" | "marketing_content" | "custom"
 *   - extends: chain up to 5 levels of policy inheritance
 *   - tool_overrides: per-tool risk level overrides
 *   - most-restrictive-wins merge semantics
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { RiskLevel, RiskRule, RiskEngine, builtinRules, riskOrd } from "./risk.js";

export type ComplianceMode =
  | "hipaa" | "sox" | "pci" | "legal"
  | "hr" | "clinical" | "research"
  | "supply_chain" | "supply_chain_sap"
  | "marketing_content"
  | "custom";

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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return value === RiskLevel.LOW || value === RiskLevel.MEDIUM || value === RiskLevel.HIGH;
}

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
  hr: {
    extra_rules: [
      { name: "hr_termination", tool: "*", pattern: "(?:^|[^a-zA-Z])(terminat|offboard|severance|separation|final_paycheck|exit_interview|deactivat|remove_access)", risk: RiskLevel.HIGH, description: "Employee termination/offboarding" },
      { name: "hr_compensation", tool: "*", pattern: "(?:^|[^a-zA-Z])(salary|compensation|bonus|equity_grant|stock_option|wage)\\s*[:=]", risk: RiskLevel.HIGH, description: "Compensation data mutation" },
      { name: "hr_bulk_ops", tool: "*", pattern: "(?:^|[^a-zA-Z])(bulk_assign|mass_update|batch.*employee|bulk_send.*(?:feedback|review|offer))", risk: RiskLevel.HIGH, description: "HR bulk operations" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  clinical: {
    // Clinical extends HIPAA: inherits PHI export/transmission rules + adds clinical order rules.
    // Use loadPolicy with extends to layer on top of hipaa.
    tool_overrides: {
      "WebFetch": RiskLevel.MEDIUM,
      "WebSearch": RiskLevel.MEDIUM,
    },
    extra_rules: [
      // HIPAA baseline rules
      { name: "hipaa_phi_export", tool: "*", pattern: "(?:^|[^a-zA-Z])(export|download|extract).*(?:patient|medical|health|PHI)", risk: RiskLevel.HIGH, description: "PHI data export" },
      { name: "hipaa_external_send", tool: "*", pattern: "(?:^|[^a-zA-Z])(send|email|fax|transmit).*(?:patient|medical|record)", risk: RiskLevel.HIGH, description: "External PHI transmission" },
      // Clinical-specific rules
      { name: "clinical_medication_order", tool: "*", pattern: "(?:^|[^a-zA-Z])(prescribe|medication_order|administer|dispense|titrate|discontinue)", risk: RiskLevel.HIGH, description: "Medication order — patient safety" },
      { name: "clinical_procedure_schedule", tool: "*", pattern: "(?:^|[^a-zA-Z])(schedule_procedure|surgery|intervention|cancel_order)", risk: RiskLevel.HIGH, description: "Clinical procedure scheduling" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  research: {
    // Research: 45 CFR 46 (Common Rule), less restrictive than HIPAA for de-identified data.
    extra_rules: [
      { name: "research_data_mutation", tool: "*", pattern: "(?:^|[^a-zA-Z])(INSERT|UPDATE|DELETE|ALTER).*(?:trial|experiment|protocol|sample|specimen)", risk: RiskLevel.HIGH, description: "Research data mutation — data integrity" },
      { name: "research_export", tool: "*", pattern: "(?:^|[^a-zA-Z])(export|download|extract).*(?:trial|experiment|patient|subject|participant)", risk: RiskLevel.HIGH, description: "Research data export" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.MEDIUM,
    require_scope_boundary: true,
  },
  supply_chain: {
    extra_rules: [
      { name: "sc_procurement", tool: "*", pattern: "(?:^|[^a-zA-Z])(purchase_order|vendor_invoice|confirm_receipt|goods_receipt|invoice_approval|po_confirm)", risk: RiskLevel.HIGH, description: "Procurement operation" },
      { name: "sc_inventory", tool: "*", pattern: "(?:^|[^a-zA-Z])(inventory_adjust|stock_update|warehouse.*move|cycle_count)", risk: RiskLevel.HIGH, description: "Inventory mutation" },
      { name: "sc_shipment", tool: "*", pattern: "(?:^|[^a-zA-Z])(re[_-]?route|reroute|divert|hold_shipment|release_shipment)", risk: RiskLevel.HIGH, description: "Shipment routing change" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  supply_chain_sap: {
    // SAP-specific extensions on top of base supply_chain preset
    extra_rules: [
      { name: "sc_procurement", tool: "*", pattern: "(?:^|[^a-zA-Z])(purchase_order|vendor_invoice|confirm_receipt|goods_receipt|invoice_approval|po_confirm)", risk: RiskLevel.HIGH, description: "Procurement operation" },
      { name: "sc_inventory", tool: "*", pattern: "(?:^|[^a-zA-Z])(inventory_adjust|stock_update|warehouse.*move|cycle_count)", risk: RiskLevel.HIGH, description: "Inventory mutation" },
      { name: "sc_shipment", tool: "*", pattern: "(?:^|[^a-zA-Z])(re[_-]?route|reroute|divert|hold_shipment|release_shipment)", risk: RiskLevel.HIGH, description: "Shipment routing change" },
      { name: "sap_mm_mutation", tool: "*", pattern: "(?:^|[^a-zA-Z])(MIGO|MIRO|ME21N|ME22N|ME23N|MB1A|MB1B|MB1C)(?:$|[^a-zA-Z])", risk: RiskLevel.HIGH, description: "SAP MM transaction codes" },
      { name: "sap_fi_mutation", tool: "*", pattern: "(?:^|[^a-zA-Z])(FB01|FB50|F-02|F-04|FK01|FBL1N)(?:$|[^a-zA-Z])", risk: RiskLevel.HIGH, description: "SAP FI transaction codes" },
    ],
    blocked_tools: [],
    max_risk_auto_allow: RiskLevel.LOW,
    require_scope_boundary: true,
  },
  marketing_content: {
    extra_rules: [
      { name: "mkt_social_post", tool: "*", pattern: "(?:^|[^a-zA-Z])(create_tweet|schedule_tweet|post_tweet|publish_post|schedule_post|create_reel|publish_story|upload_video)", risk: RiskLevel.HIGH, description: "Social media posting — brand risk" },
      { name: "mkt_list_destruct", tool: "*", pattern: "(?:^|[^a-zA-Z])(bulk_unsubscribe|suppress_all|delete.*list|purge.*list|unsubscribe_all)", risk: RiskLevel.HIGH, description: "Marketing list destruction" },
      { name: "mkt_campaign_activate", tool: "*", pattern: "(?:^|[^a-zA-Z])(activate_campaign|launch_campaign|send_campaign|go_live)", risk: RiskLevel.HIGH, description: "Campaign activation — irreversible" },
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
    if (depth > 0) {
      throw new Error(`extended policy file not found: ${policyPath}`);
    }
    return {};
  }
  let rawValue: unknown;
  try {
    rawValue = JSON.parse(readFileSync(policyPath, "utf-8"));
  } catch {
    throw new Error(`failed to parse policy file: ${policyPath}`);
  }
  if (!isPlainObject(rawValue)) {
    throw new Error(`policy file must contain a JSON object: ${policyPath}`);
  }
  const raw = rawValue as PolicyConfig;
  if (raw.extends !== undefined && typeof raw.extends !== "string") {
    throw new Error(`policy "extends" must be a string: ${policyPath}`);
  }

  // Resolve extends
  let resolved: PolicyConfig = raw;
  if (raw.extends) {
    const basePath = resolve(dirname(policyPath), raw.extends);
    const base = loadPolicy(basePath, depth + 1);
    resolved = mergePolicies(base, raw);
  }

  // Apply compliance preset as base
  if (resolved.compliance_mode && resolved.compliance_mode !== "custom") {
    const preset = PRESETS[resolved.compliance_mode];
    if (preset) {
      return mergePolicies(preset as PolicyConfig, resolved);
    }
  }

  return resolved;
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

  // Tool overrides act as a minimum risk floor for matching tools.
  if (config.tool_overrides) {
    for (const [tool, risk] of Object.entries(config.tool_overrides)) {
      rules.push(new RiskRule({
        name: `policy_override_${tool}`,
        tool,
        pattern: ".*",
        risk,
        description: `Policy risk floor for ${tool}`,
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

  if (config.extends !== undefined && typeof config.extends !== "string") {
    errors.push("extends must be a string");
  }

  if (config.extra_rules !== undefined && !Array.isArray(config.extra_rules)) {
    errors.push("extra_rules must be an array");
  } else if (config.extra_rules) {
    for (const [index, r] of config.extra_rules.entries()) {
      if (!isPlainObject(r)) {
        errors.push(`extra_rules[${index}] must be an object`);
        continue;
      }
      if (!r.name) errors.push("extra_rules entry missing name");
      if (!r.tool) errors.push(`extra_rules "${r.name}" missing tool`);
      if (!r.pattern) errors.push(`extra_rules "${r.name}" missing pattern`);
      try {
        new RegExp(r.pattern, "i");
      } catch {
        errors.push(`extra_rules "${r.name}" has invalid regex: ${r.pattern}`);
      }
      if (!isRiskLevel(r.risk)) {
        errors.push(`extra_rules "${r.name}" has invalid risk: ${r.risk}`);
      }
    }
  }

  if (config.tool_overrides !== undefined && !isPlainObject(config.tool_overrides)) {
    errors.push("tool_overrides must be an object");
  } else if (config.tool_overrides) {
    for (const [tool, risk] of Object.entries(config.tool_overrides)) {
      if (!isRiskLevel(risk)) {
        errors.push(`tool_overrides "${tool}" has invalid risk: ${risk}`);
      }
    }
  }

  if (config.blocked_tools !== undefined && !isStringArray(config.blocked_tools)) {
    errors.push("blocked_tools must be an array of strings");
  } else if (config.blocked_tools?.length && config.blocked_tools.some(t => !t)) {
    warnings.push("blocked_tools contains empty strings");
  }

  if (config.max_risk_auto_allow !== undefined && !isRiskLevel(config.max_risk_auto_allow)) {
    errors.push(`max_risk_auto_allow has invalid risk: ${config.max_risk_auto_allow}`);
  }

  if (
    config.require_scope_boundary !== undefined &&
    typeof config.require_scope_boundary !== "boolean"
  ) {
    errors.push("require_scope_boundary must be a boolean");
  }

  return { valid: errors.length === 0, errors, warnings };
}
