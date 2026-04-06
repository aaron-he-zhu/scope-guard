#!/usr/bin/env python3
import json
from pathlib import Path

try:
    import jsonschema
except ImportError as e:
    raise SystemExit("Please install requirements-dev.txt before running validation.") from e

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SHARED = ROOT / "shared"

task_schema = json.loads((SHARED / "task-contract.schema.json").read_text(encoding="utf-8"))
result_schema = json.loads((SHARED / "downstream-result.schema.json").read_text(encoding="utf-8"))

task_examples = [
    "memo-draft-handoff.json",
    "email-draft-handoff.json",
    "research-handoff.json",
    "coding-handoff.json",
]

result_examples = [
    "document-result.json",
    "action-preview-result.json",
    "blocked-action-result.json",
    "partial-document-result.json",
]

errors = []

def validate_group(schema, names):
    for name in names:
        path = EXAMPLES / name
        data = json.loads(path.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as exc:
            errors.append(f"{name}: {exc.message}")

validate_group(task_schema, task_examples)
validate_group(result_schema, result_examples)

if errors:
    print("Validation failed:")
    for err in errors:
        print(f"- {err}")
    raise SystemExit(1)

print("All example files validate successfully.")
