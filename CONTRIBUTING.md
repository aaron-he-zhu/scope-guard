# Contributing to Scope Guard

Thank you for your interest in contributing to Scope Guard!

## Getting started

```bash
git clone https://github.com/aaron-he-zhu/scope-guard.git
cd scope-guard
npm install
npm run build
npm test
```

## Development workflow

1. Create a branch from `main`
2. Make your changes in `src/`
3. Run `npm run build && npm test` — all tests must pass
4. For packaging or hook changes, also run `npm pack --json` and `npm run test:package-smoke -- <tarball>`
5. Commit with a clear message describing **what** and **why**
6. Open a pull request

## Project structure

```
src/
  checker.ts   — ScopeChecker: verdict logic (allow/warn/block)
  risk.ts      — RiskEngine: regex-based risk classification
  scope.ts     — ScopeBoundary: file/dir scope management
  audit.ts     — AuditLog: JSONL append-only audit trail
  hook.ts      — Claude Code PreToolUse hook entry point
  hook-post.ts — Claude Code PostToolUse hook entry point
  index.ts     — OpenClaw plugin entry point
  test.ts      — Full test suite (node:test)
scripts/
  package-smoke.mjs — package/install/hook smoke test for CI and local verification
```

## Adding a risk rule

To add a new built-in risk rule, edit `builtinRules()` in `src/risk.ts`:

```typescript
new RiskRule({
  name: "my_rule",
  tool: "Bash",           // or "*" for all tools
  pattern: "dangerous_command",  // regex, case-insensitive
  risk: RiskLevel.HIGH,   // HIGH, MEDIUM, or LOW
  description: "Why this is risky",
}),
```

Then add a corresponding test in `src/test.ts` and update the rule count assertion.

## Pull request guidelines

- Keep PRs focused — one fix or feature per PR
- All tests must pass (`npm test`)
- Security-critical changes require extra scrutiny — scope-guard is a safety tool
- Update CHANGELOG.md for user-facing changes

## Reporting security issues

For security vulnerabilities, please email the maintainer directly instead of opening a public issue. See the repository contact information.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards.
