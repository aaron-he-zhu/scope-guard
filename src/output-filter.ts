/**
 * OutputFilter — post-tool-use content filtering.
 *
 * Uses ContentScanner to detect PII/PHI/secrets in tool output
 * and optionally redacts them before the output reaches the model.
 */

import { ContentScanner, type ContentFlag, type ContentScanResult } from "./content.js";
import { RiskLevel, riskOrd } from "./risk.js";

export interface FilterResult {
  filtered: boolean;
  original_length: number;
  filtered_length: number;
  redacted_patterns: string[];
  risk_level: RiskLevel;
}

export class OutputFilter {
  private scanner: ContentScanner;

  constructor(scanner?: ContentScanner) {
    this.scanner = scanner ?? new ContentScanner();
  }

  /** Scan output and return filter metadata (no redaction). */
  scan(output: string): FilterResult {
    const scanResult = this.scanner.scan(output);
    return {
      filtered: scanResult.flags.length > 0,
      original_length: output.length,
      filtered_length: output.length,
      redacted_patterns: scanResult.flags.map(f => f.pattern_name),
      risk_level: scanResult.highest_risk,
    };
  }

  /** Scan and redact sensitive patterns from output. */
  redact(output: string): { text: string; result: FilterResult } {
    const scanResult = this.scanner.scan(output);
    if (scanResult.flags.length === 0) {
      return {
        text: output,
        result: {
          filtered: false,
          original_length: output.length,
          filtered_length: output.length,
          redacted_patterns: [],
          risk_level: RiskLevel.LOW,
        },
      };
    }

    let text = output;
    const redacted: string[] = [];

    for (const flag of scanResult.flags) {
      const re = ContentScanner.getPattern(flag.pattern_name);
      if (re) {
        const before = text;
        text = text.replace(re, `[REDACTED:${flag.pattern_name}]`);
        if (text !== before) redacted.push(flag.pattern_name);
      }
    }

    return {
      text,
      result: {
        filtered: redacted.length > 0,
        original_length: output.length,
        filtered_length: text.length,
        redacted_patterns: redacted,
        risk_level: scanResult.highest_risk,
      },
    };
  }
}
