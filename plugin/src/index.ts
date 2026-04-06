/**
 * Preflight Scope Guard — OpenClaw Plugin Entry Point
 *
 * Registers a `before_tool_call` hook that enforces scope boundaries
 * and risk-based approval gates on every tool call.
 *
 * Dual-layer enforcement:
 *   1. SKILL.md (prompt-level) — bundled under ./skills/preflight/
 *   2. This hook (deterministic) — blocks/approves via exit semantics
 */

import { join } from "node:path";
import { ScopeChecker, CheckVerdict } from "./checker.js";
import { RiskEngine } from "./risk.js";
import { ScopeBoundary } from "./scope.js";
import { AuditLog } from "./audit.js";

interface PluginConfig {
  scopePath?: string;
  rulesPath?: string;
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
  id: "preflight",
  name: "Preflight Scope Guard",

  register(api: PluginAPI) {
    api.registerHook(
      "before_tool_call",
      async (event: BeforeToolCallEvent) => {
        try {
          const config = api.getConfig();
          const workspacePath = api.getWorkspacePath();

          // Resolve paths from config or defaults
          const scopePath = config.scopePath
            ? join(workspacePath, config.scopePath)
            : join(workspacePath, ".claude", "scope-boundary.json");

          const auditLogPath = config.auditLogPath
            ? join(workspacePath, config.auditLogPath)
            : join(workspacePath, ".claude", "preflight-audit.jsonl");

          // Load scope boundary
          const boundary = ScopeBoundary.load(scopePath);

          // Build risk engine (builtin rules only in plugin mode)
          const engine = RiskEngine.default();

          // Run scope check
          const checker = new ScopeChecker(boundary, engine);
          const result = checker.check(event.toolName, event.params);

          // Write audit log
          try {
            const audit = new AuditLog(auditLogPath);
            audit.record(result);
          } catch (e) {
            console.error(`[preflight] audit write failed: ${e}`);
          }

          // Map verdict to OpenClaw hook semantics
          switch (result.verdict) {
            case CheckVerdict.BLOCK:
              return {
                block: true,
                blockReason: `[preflight] BLOCKED: ${result.reason} (target: ${result.target})`,
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
          console.error(`[preflight] internal error: ${e}`);
          return {
            block: true,
            blockReason: "[preflight] internal error — fail closed",
          };
        }
      },
      {
        name: "preflight.scope-check",
        description:
          "Enforces scope boundaries and risk-based approval gates on every tool call",
      },
    );
  },
});
