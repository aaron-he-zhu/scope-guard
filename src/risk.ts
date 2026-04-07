/**
 * Rule-based risk assessment engine.
 */

export enum RiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
}

const RISK_ORD: Record<string, number> = { low: 0, medium: 1, high: 2 };

export function riskOrd(r: RiskLevel): number {
  return RISK_ORD[r] ?? 0;
}

export interface RiskRuleConfig {
  name: string;
  tool: string;
  pattern: string;
  risk: RiskLevel;
  description?: string;
}

export class RiskRule {
  readonly name: string;
  readonly tool: string;
  readonly pattern: string;
  readonly risk: RiskLevel;
  readonly description: string;
  private readonly compiled: RegExp;

  constructor(config: RiskRuleConfig) {
    this.name = config.name;
    this.tool = config.tool;
    this.pattern = config.pattern;
    this.risk = config.risk;
    this.description = config.description ?? "";

    try {
      this.compiled = new RegExp(config.pattern, "i");
    } catch (e) {
      throw new Error(
        `Invalid regex in rule '${config.name}': ${e instanceof Error ? e.message : e}`,
      );
    }
  }

  matches(toolName: string, paramsStr: string): boolean {
    if (this.tool !== "*" && this.tool.toLowerCase() !== toolName.toLowerCase()) {
      return false;
    }
    return this.compiled.test(paramsStr) || this.compiled.test(toolName);
  }
}

export class RiskEngine {
  readonly rules: RiskRule[];

  constructor(rules?: RiskRule[]) {
    this.rules = rules ?? [];
  }

  /** Return the highest risk level matched by any rule. */
  assess(toolName: string, params: Record<string, unknown> | string): RiskLevel {
    const paramsStr = paramsToStr(params);
    let highest = RiskLevel.LOW;
    for (const rule of this.rules) {
      if (rule.matches(toolName, paramsStr) && riskOrd(rule.risk) > riskOrd(highest)) {
        highest = rule.risk;
      }
    }
    return highest;
  }

  /** Return all rules that match the given tool call. */
  matchingRules(toolName: string, params: Record<string, unknown> | string): RiskRule[] {
    const paramsStr = paramsToStr(params);
    return this.rules.filter((r) => r.matches(toolName, paramsStr));
  }

  /** Create a RiskEngine with the default built-in rules. */
  static default(): RiskEngine {
    return new RiskEngine(builtinRules());
  }
}

function paramsToStr(params: Record<string, unknown> | string): string {
  return typeof params === "string" ? params : JSON.stringify(params);
}

/** Built-in risk rules. */
export function builtinRules(): RiskRule[] {
  return [
    // --- HIGH risk ---
    new RiskRule({
      name: "destructive_rm",
      tool: "Bash",
      pattern: "\\b(rm\\s+(-rf|-r\\s|--recursive)|rmdir)\\b",
      risk: RiskLevel.HIGH,
      description: "Recursive file deletion",
    }),
    new RiskRule({
      name: "force_push",
      tool: "Bash",
      pattern: "git\\s+push\\s+.*(--force|-f)\\b",
      risk: RiskLevel.HIGH,
      description: "Force push overwrites remote history",
    }),
    new RiskRule({
      name: "git_reset_hard",
      tool: "Bash",
      pattern: "git\\s+reset\\s+--hard",
      risk: RiskLevel.HIGH,
      description: "Hard reset discards all uncommitted changes",
    }),
    new RiskRule({
      name: "drop_database",
      tool: "Bash",
      pattern: "\\b(drop\\s+(table|database|index|view|schema)|truncate\\s+table)\\b",
      risk: RiskLevel.HIGH,
      description: "Database destructive operations",
    }),
    new RiskRule({
      name: "secret_files",
      tool: "*",
      pattern: "\\.(env|pem|key|secret|credentials)([\"'\\s}]|$)",
      risk: RiskLevel.HIGH,
      description: "Accessing secret or credential files",
    }),
    new RiskRule({
      name: "sensitive_system_paths",
      tool: "*",
      pattern: "/etc/(shadow|passwd|sudoers)",
      risk: RiskLevel.MEDIUM,
      description: "Accessing sensitive system files",
    }),
    new RiskRule({
      name: "npm_publish",
      tool: "Bash",
      pattern: "\\bnpm\\s+publish\\b",
      risk: RiskLevel.HIGH,
      description: "Publishing to npm registry",
    }),
    new RiskRule({
      name: "docker_push",
      tool: "Bash",
      pattern: "\\bdocker\\s+push\\b",
      risk: RiskLevel.HIGH,
      description: "Pushing docker images to registry",
    }),
    new RiskRule({
      name: "curl_mutate",
      tool: "Bash",
      pattern: "(curl\\s+.*?-X\\s*(POST|PUT|DELETE|PATCH)|wget\\s+.*?--post)",
      risk: RiskLevel.HIGH,
      description: "HTTP mutation via curl or wget",
    }),
    new RiskRule({
      name: "sensitive_file_read",
      tool: "Bash",
      pattern: "\\b(cat|head|tail|less|more|strings|xxd|hexdump)\\b.*(/etc/(shadow|passwd|sudoers)|\\.(env|pem|key|secret|credentials)([\"'\\s}]|$))",
      risk: RiskLevel.MEDIUM,
      description: "Reading sensitive system or credential files",
    }),
    // --- MEDIUM risk ---
    new RiskRule({
      name: "write_file",
      tool: "Write",
      pattern: ".",
      risk: RiskLevel.MEDIUM,
      description: "Creating or overwriting a file",
    }),
    new RiskRule({
      name: "network_read",
      tool: "Bash",
      pattern: "\\b(curl|wget|http)\\b",
      risk: RiskLevel.MEDIUM,
      description: "Network read operations",
    }),
    new RiskRule({
      name: "package_install",
      tool: "Bash",
      pattern: "\\b(pip\\s+install|npm\\s+install|yarn\\s+add|apt\\s+install|brew\\s+install)\\b",
      risk: RiskLevel.MEDIUM,
      description: "Installing packages",
    }),
    new RiskRule({
      name: "git_checkout_discard",
      tool: "Bash",
      pattern: "git\\s+(checkout\\s+--\\s|restore\\s|clean\\s+-f|branch\\s+-D)",
      risk: RiskLevel.MEDIUM,
      description: "Potentially destructive git operations",
    }),
    new RiskRule({
      name: "chmod_chown",
      tool: "Bash",
      pattern: "\\b(chmod|chown)\\b",
      risk: RiskLevel.MEDIUM,
      description: "Changing file permissions or ownership",
    }),
    // --- v2: SQL + messaging + publishing ---
    new RiskRule({
      name: "sql_mutation",
      tool: "*",
      pattern: "\\b(INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM|MERGE\\s+INTO|ALTER\\s+TABLE)\\b",
      risk: RiskLevel.HIGH,
      description: "SQL data mutation — requires explicit approval",
    }),
    new RiskRule({
      name: "sql_platform_mutation",
      tool: "*",
      pattern: "\\b(CREATE\\s+OR\\s+REPLACE\\s+(TABLE|VIEW|FUNCTION)|COPY\\s+INTO|UNLOAD\\s+TO|bq\\s+extract|OPTIMIZE\\s+TABLE|VACUUM)\\b",
      risk: RiskLevel.HIGH,
      description: "Platform-specific data mutation or export",
    }),
    new RiskRule({
      name: "messaging_broadcast",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(broadcast|bulk_send|mass_email|send_campaign|blast)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Bulk messaging or broadcast — mass impact",
    }),
    new RiskRule({
      name: "messaging_single",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(send_message|send_email|post_message|send_reply|send_notification)(?:$|[^a-zA-Z])",
      risk: RiskLevel.MEDIUM,
      description: "Single message send — confirm recipient",
    }),
    new RiskRule({
      name: "publish_schedule",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(publish|schedule_send|go_live|activate_campaign|launch_campaign)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Publishing or scheduling content — potentially irreversible",
    }),
    // --- v3: Industry-specific rules ---
    // CRM / Sales
    new RiskRule({
      name: "crm_deal_mutation",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(update_deal|update_opportunity|change.*stage|set.*amount|update_amount|close.*(?:deal|opp|opportunity|account))(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "CRM deal/opportunity mutation — potential pipeline fraud",
    }),
    new RiskRule({
      name: "crm_merge_ops",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(merge_contact|merge_account|merge_deal|merge_ticket|dedupe|consolidate)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "CRM merge — permanent data loss risk",
    }),
    new RiskRule({
      name: "enrollment_mass",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(enroll_in|add_to_sequence|add_to_list|add_to_campaign|activate_workflow|trigger_workflow|bulk_enroll|subscribe_bulk)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Mass enrollment/sequence — spam/compliance risk",
    }),
    // Marketing / Social media
    new RiskRule({
      name: "social_media_post",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(create_tweet|schedule_tweet|post_tweet|publish_post|schedule_post|create_reel|publish_story|share_post|upload_video|create_article)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Social media posting — brand/reputation risk",
    }),
    new RiskRule({
      name: "marketing_list_destruct",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(bulk_unsubscribe|suppress_all|delete.*(?:list|segment)|purge.*(?:list|segment)|unsubscribe_all|bulk_suppress)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Marketing list destruction — campaign damage",
    }),
    // Clinical / Healthcare
    new RiskRule({
      name: "clinical_order",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(prescribe|order.*medication|medication_order|administer|dispense|titrate|discontinue)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Clinical medication order ��� patient safety critical",
    }),
    new RiskRule({
      name: "clinical_procedure",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(schedule_procedure|surgery|intervention|cancel_order|schedule_surgery)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Clinical procedure scheduling — patient safety critical",
    }),
    // Supply chain / Procurement
    new RiskRule({
      name: "procurement_order",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(purchase_order|vendor_invoice|confirm_receipt|goods_receipt|three_way_match|invoice_approval|material_receipt|po_confirm)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Procurement operation — financial commitment",
    }),
    new RiskRule({
      name: "inventory_adjust",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(inventory_adjust|stock_update|warehouse.*move|cycle_count|stock_transfer)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Inventory mutation — asset integrity risk",
    }),
    new RiskRule({
      name: "shipment_divert",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(re[_-]?route|reroute|divert|hold_shipment|release_shipment|shipment_hold|in_transit_change|carrier.*change)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Shipment routing change — cargo theft/trade compliance risk",
    }),
    // HR / People ops
    new RiskRule({
      name: "termination_ops",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(terminat|offboard|exit_interview|severance|final_paycheck|separation|deactivat|remove_access|last_day)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Employee termination/offboarding — sensitive HR operation",
    }),
    // Legal
    new RiskRule({
      name: "litigation_hold",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(litigation[_.]hold|legal[_.]hold|preserve|custodian|hold_notice|retention_hold|delete_hold|modify_hold)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Litigation hold operation — evidence preservation critical",
    }),
    // IaC / DevOps
    new RiskRule({
      name: "iac_destructive",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(terraform.*destroy|kubectl.*delete|helm.*uninstall|pulumi.*destroy|cdk.*destroy)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Infrastructure destruction — service disruption risk",
    }),
    new RiskRule({
      name: "iac_apply",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(terraform.*apply|helm.*(?:upgrade|install)|kubectl.*apply|pulumi.*up|cdk.*deploy)(?:$|[^a-zA-Z])",
      risk: RiskLevel.MEDIUM,
      description: "Infrastructure apply — review required before mutation",
    }),
    // Finance / Accounting
    new RiskRule({
      name: "financial_reversal",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(reverse.*(?:journal|entry|posting)|reopen.*period|reclass|reclassify|override_control|void.*(?:check|payment))(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Financial reversal/reclassification — SOX critical",
    }),
    new RiskRule({
      name: "payment_release",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(create_payout|release_payment|wire_transfer|approve_payment|ach_transfer|process_disbursement)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Payment release/wire transfer — fraud risk",
    }),
    new RiskRule({
      name: "tax_adjustment",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(tax_reversal|adjust.*(?:tax|provision)|estimated_tax|write_off)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Tax/provision adjustment — audit-sensitive",
    }),
    // Support
    new RiskRule({
      name: "support_bulk_ops",
      tool: "*",
      pattern: "(?:^|[^a-zA-Z])(bulk_assign|escalate_tickets|merge.*ticket|reassign_all|bulk_close)(?:$|[^a-zA-Z])",
      risk: RiskLevel.HIGH,
      description: "Support bulk operations — service disruption risk",
    }),
  ];
}
