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
  ];
}
