from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from securelens.exceptions import RuleLoadError
from securelens.scanner import Rule, Severity


def _parse_rule(raw: dict[str, Any], source: Path) -> Rule:
    required = ("id", "title", "pattern", "severity", "description", "suggestion")
    missing = [k for k in required if k not in raw]
    if missing:
        raise RuleLoadError(str(source), f"Rule missing required keys: {missing}")

    flags = re.IGNORECASE if raw.get("case_insensitive") else 0
    try:
        compiled = re.compile(raw["pattern"], flags)
        severity = Severity[raw["severity"].upper()]
    except re.error as exc:
        raise RuleLoadError(
            str(source), f"Invalid regex in rule '{raw['id']}': {exc}"
        ) from exc
    except KeyError:
        raise RuleLoadError(
            str(source),
            f"Unknown severity '{raw['severity']}' in rule '{raw['id']}'",
        )

    return Rule(
        rule_id=raw["id"],
        title=raw["title"],
        pattern=compiled,
        severity=severity,
        description=raw["description"],
        suggestion=raw["suggestion"],
        cwe=raw.get("cwe", ""),
    )


def load_rules(rules_file: Path) -> list[Rule]:
    """Load Rule objects from a YAML file.

    Raises RuleLoadError on any failure so callers can provide a helpful
    message without catching generic exceptions.
    """
    if not rules_file.exists():
        raise RuleLoadError(str(rules_file), "File not found")

    try:
        import yaml
    except ImportError as exc:
        raise RuleLoadError(
            str(rules_file),
            "PyYAML is not installed. Run: pip install pyyaml",
        ) from exc

    try:
        text = rules_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(str(rules_file), str(exc)) from exc

    try:
        data = yaml.safe_load(text)
    except Exception as exc:
        raise RuleLoadError(str(rules_file), f"YAML parse error: {exc}") from exc

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError(str(rules_file), "Expected a top-level 'rules' list")

    return [_parse_rule(r, rules_file) for r in data["rules"]]
