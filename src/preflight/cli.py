"""CLI entry point: `preflight init`, `preflight status`, `preflight check`."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

CLAUDE_DIR = ".claude"
SCOPE_FILE = "scope-boundary.json"
SETTINGS_FILE = "settings.json"
SKILL_DIR_NAME = "skill"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="preflight",
        description="Scope guard for agentic AI systems.",
    )
    sub = parser.add_subparsers(dest="command")

    # init
    init_p = sub.add_parser("init", help="Set up preflight in the current project")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing config")

    # status
    sub.add_parser("status", help="Show current scope boundary and audit summary")

    # check (for manual testing)
    check_p = sub.add_parser("check", help="Check a tool call against current scope")
    check_p.add_argument("tool", help="Tool name (e.g. Edit, Bash, Write)")
    check_p.add_argument("params_json", help="Tool params as JSON string")

    args = parser.parse_args(argv)

    if args.command == "init":
        _cmd_init(args)
    elif args.command == "status":
        _cmd_status()
    elif args.command == "check":
        _cmd_check(args)
    else:
        parser.print_help()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def _cmd_init(args: argparse.Namespace) -> None:
    claude_dir = Path(CLAUDE_DIR)
    claude_dir.mkdir(exist_ok=True)

    # 1. Write empty scope boundary
    scope_path = claude_dir / SCOPE_FILE
    if scope_path.exists() and not args.force:
        print(f"  {scope_path} already exists (use --force to overwrite)")
    else:
        from preflight.scope import ScopeBoundary
        ScopeBoundary().save(scope_path)
        print(f"  Created {scope_path}")

    # 2. Copy default risk rules
    rules_dst = claude_dir / "preflight-rules.yaml"
    rules_src = Path(__file__).parent / "rules" / "default.yaml"
    if rules_dst.exists() and not args.force:
        print(f"  {rules_dst} already exists (use --force to overwrite)")
    elif rules_src.exists():
        shutil.copy2(rules_src, rules_dst)
        print(f"  Created {rules_dst}")

    # 3. Copy SKILL.md to skills directory
    skill_dst = claude_dir / "skills" / "scope-guard" / "SKILL.md"
    skill_src = Path(__file__).parent / "data" / "SKILL.md"
    if not skill_src.exists():
        # Fallback to repo root
        skill_src = Path(__file__).parent.parent.parent / "skill" / "SKILL.md"
    if skill_src.exists():
        skill_dst.parent.mkdir(parents=True, exist_ok=True)
        if skill_dst.exists() and not args.force:
            print(f"  {skill_dst} already exists (use --force to overwrite)")
        else:
            shutil.copy2(skill_src, skill_dst)
            print(f"  Created {skill_dst}")

    # 4. Print hook configuration instructions
    print()
    print("  Add this to your .claude/settings.json to enable the hook:")
    print()
    hook_config = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python -m preflight.checker",
                        }
                    ],
                }
            ]
        }
    }
    print(f"  {json.dumps(hook_config, indent=2)}")
    print()
    print("  Done. Run `preflight status` to verify setup.")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def _cmd_status() -> None:
    from preflight.scope import ScopeBoundary
    from preflight.audit import AuditLog

    scope_path = Path(CLAUDE_DIR) / SCOPE_FILE
    boundary = ScopeBoundary.load(scope_path)

    print("=== Preflight Status ===")
    print()

    if boundary.is_empty:
        print("Scope: (none set — will use risk-only mode)")
    else:
        print(f"Scope: {len(boundary.files_in_scope)} files, {len(boundary.dirs_in_scope)} dirs")
        if boundary.files_in_scope:
            for f in boundary.files_in_scope[:10]:
                print(f"  file: {f}")
            if len(boundary.files_in_scope) > 10:
                print(f"  ... and {len(boundary.files_in_scope) - 10} more")
        if boundary.dirs_in_scope:
            for d in boundary.dirs_in_scope[:10]:
                print(f"  dir:  {d}")
        print(f"Risk level: {boundary.risk_level.value}")
        print(f"Approval required: {boundary.approval_required}")
        if boundary.assumptions:
            print(f"Assumptions: {len(boundary.assumptions)}")
            for a in boundary.assumptions:
                mark = "[v]" if a.verified else "[ ]"
                print(f"  {mark} {a.text}")
        if boundary.task_summary:
            print(f"Task: {boundary.task_summary}")
        if boundary.revisions:
            print(f"Revisions: {len(boundary.revisions)}")

    print()
    audit = AuditLog.default()
    summary = audit.summary()
    if summary["total"] == 0:
        print("Audit: no entries yet")
    else:
        print(f"Audit: {summary['total']} checks")
        print(f"  allow: {summary['verdicts'].get('allow', 0)}")
        print(f"  warn:  {summary['verdicts'].get('warn', 0)}")
        print(f"  block: {summary['verdicts'].get('block', 0)}")
        print(f"  scope violations: {summary['scope_violations']}")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def _cmd_check(args: argparse.Namespace) -> None:
    from preflight.scope import ScopeBoundary
    from preflight.risk import RiskEngine
    from preflight.checker import ScopeChecker

    scope_path = Path(CLAUDE_DIR) / SCOPE_FILE
    boundary = ScopeBoundary.load(scope_path)
    engine = RiskEngine.default()
    checker = ScopeChecker(boundary, engine)

    try:
        params = json.loads(args.params_json)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON — {exc}", file=sys.stderr)
        sys.exit(1)
    result = checker.check(args.tool, params)

    print(json.dumps(result.to_dict(), indent=2))
    sys.exit({"allow": 0, "warn": 1, "block": 2}[result.verdict.value])


if __name__ == "__main__":
    main()
