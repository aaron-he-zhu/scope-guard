/**
 * ContentScanner — regex-based detection of PII, PHI, secrets, and exfiltration patterns.
 * Zero dependencies. Scanning only escalates verdicts, never suppresses.
 */

import { RiskLevel, riskOrd } from "./risk.js";

export interface ContentFlag {
  type: "pii" | "phi" | "secret" | "exfiltration";
  pattern_name: string;
  description: string;
}

export interface ContentScanResult {
  flags: ContentFlag[];
  highest_risk: RiskLevel;
}

interface ScanPattern {
  type: ContentFlag["type"];
  name: string;
  re: RegExp;
  desc: string;
  risk: RiskLevel;
}

const PATTERNS: ScanPattern[] = [
  // PII
  { type: "pii", name: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/, desc: "SSN pattern", risk: RiskLevel.HIGH },
  { type: "pii", name: "credit_card", re: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, desc: "Credit card number", risk: RiskLevel.HIGH },
  { type: "pii", name: "phone", re: /\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, desc: "Phone number", risk: RiskLevel.MEDIUM },
  // PHI
  { type: "phi", name: "mrn", re: /\bMRN[:\s#]*\d{5,}\b/i, desc: "Medical record number", risk: RiskLevel.HIGH },
  { type: "phi", name: "dob_label", re: /\b(?:date\s+of\s+birth|DOB)[:\s]+\d/i, desc: "Date of birth label", risk: RiskLevel.HIGH },
  { type: "phi", name: "diagnosis", re: /\b(?:ICD-?10|diagnosis\s+code)[:\s]*[A-Z]\d/i, desc: "ICD-10 diagnosis code", risk: RiskLevel.HIGH },
  // Secrets
  { type: "secret", name: "api_key_assign", re: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S{8,}/i, desc: "API key assignment", risk: RiskLevel.HIGH },
  { type: "secret", name: "bearer_token", re: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, desc: "Bearer token", risk: RiskLevel.HIGH },
  // Exfiltration
  { type: "exfiltration", name: "base64_large", re: /[A-Za-z0-9+/=]{200,}/, desc: "Large base64 blob", risk: RiskLevel.MEDIUM },
];

export class ContentScanner {
  scan(text: string): ContentScanResult {
    const flags: ContentFlag[] = [];
    let highest = RiskLevel.LOW;
    for (const p of PATTERNS) {
      if (p.re.test(text)) {
        flags.push({ type: p.type, pattern_name: p.name, description: p.desc });
        if (riskOrd(p.risk) > riskOrd(highest)) highest = p.risk;
      }
    }
    return { flags, highest_risk: highest };
  }

  /** Get the compiled RegExp for a given pattern name (for redaction). */
  static getPattern(name: string): RegExp | undefined {
    const found = PATTERNS.find(p => p.name === name);
    return found ? new RegExp(found.re.source, found.re.flags + (found.re.flags.includes("g") ? "" : "g")) : undefined;
  }
}
