/**
 * Scope Guard — OpenClaw Plugin Entry Point
 *
 * Registers a `before_tool_call` hook that enforces scope boundaries
 * and risk-based approval gates on every tool call.
 *
 * Dual-layer enforcement:
 *   1. SKILL.md (prompt-level) — bundled under ./skills/scope-guard/
 *   2. This hook (deterministic) — blocks/approves via exit semantics
 */

import { ScopeChecker, CheckVerdict } from "./checker.js";
import { AuditLog } from "./audit.js";
import { loadEnforcementRuntime } from "./runtime.js";

interface PluginConfig {
  scopePath?: string;
  rulesPath?: string;
  policyPath?: string;
  auditLogPath?: string;
}

interface BeforeToolCallEvent {
  toolName: string;
  toolCallId: string;
  params: Record<string, unknown>;
}

interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: boolean;
  metadata?: Record<string, unknown>;
}

interface PluginAPI {
  registerHook(
    event: string,
    handler: (event: BeforeToolCallEvent, ctx: unknown) => Promise<BeforeToolCallResult>,
    options?: { name?: string; description?: string },
  ): void;
  getConfig(): PluginConfig;
  getWorkspacePath(): string;
}

interface PluginEntry {
  id: string;
  name: string;
  register(api: PluginAPI): void;
}

function definePluginEntry(entry: PluginEntry): PluginEntry {
  return entry;
}

export default definePluginEntry({
  id: "scope-guard",
  name: "Scope Guard",

  register(api: PluginAPI) {
    api.registerHook(
      "before_tool_call",
      async (event: BeforeToolCallEvent) => {
        try {
          const config = api.getConfig();
          const workspacePath = api.getWorkspacePath();
          const runtime = loadEnforcementRuntime(workspacePath, {
            scopePath: config.scopePath,
            policyPath: config.policyPath ?? config.rulesPath,
            auditLogPath: config.auditLogPath,
          });
          const result = runtime.checker.check(event.toolName, event.params);

          // Write audit log
          try {
            const audit = new AuditLog(runtime.auditLogPath);
            audit.record(result);
          } catch (e) {
            console.error(`[scope-guard] audit write failed: ${e}`);
          }

          // Map verdict to OpenClaw hook semantics
          switch (result.verdict) {
            case CheckVerdict.BLOCK:
              return {
                block: true,
                blockReason: `[scope-guard] BLOCKED: ${result.reason} (target: ${result.target})`,
              };
            case CheckVerdict.ESCALATE:
              return {
                requireApproval: true,
                metadata: { escalation_reason: result.escalation_reason ?? result.reason, requires_human: true },
              };
            case CheckVerdict.WARN:
              return {
                requireApproval: true,
              };
            case CheckVerdict.ALLOW:
            default:
              return {};
          }
        } catch (e) {
          // Safety tool must fail closed — block on internal errors
          console.error(`[scope-guard] internal error: ${e}`);
          return {
            block: true,
            blockReason: "[scope-guard] internal error — fail closed",
          };
        }
      },
      {
        name: "scope-guard.check",
        description:
          "Enforces scope boundaries and risk-based approval gates on every tool call",
      },
    );
  },
});
