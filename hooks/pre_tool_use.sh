#!/usr/bin/env bash
# Scope Guard PreToolUse hook for Claude Code.
# Reads tool call JSON from stdin, runs the scope checker, and exits
# with the appropriate code (0=allow, 1=warn, 2=block).
#
# Install: add this to .claude/settings.json under hooks.PreToolUse

set -euo pipefail

# Pass stdin through to the Python checker.
python -m scope_guard.checker
