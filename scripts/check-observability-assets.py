#!/usr/bin/env python3
"""Validate bundled observability assets without adding a YAML dependency."""

from __future__ import annotations

import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ROOT / "deploy/observability/prometheus-rules.yaml"
DASHBOARD = ROOT / "deploy/observability/grafana-dashboard.json"
METRIC = re.compile(r"\bpeerward_[a-z0-9_:]+\b")
FORBIDDEN = ("mesh_id", "peer_id", "relay_id", "destination", "endpoint", "dns_question")


def implemented_metrics() -> set[str]:
    values: set[str] = set()
    for base in (ROOT / "crates", ROOT / "apps"):
        for path in base.rglob("*"):
            if path.suffix not in {".rs", ".kt"} or "build" in path.parts:
                continue
            values.update(METRIC.findall(path.read_text(encoding="utf-8")))
    return values


def validate_rules(text: str) -> set[str]:
    alerts: dict[str, dict[str, bool]] = {}
    current: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if "\t" in line or line.rstrip() != line:
            raise SystemExit(f"{RULES}:{number}: tabs and trailing whitespace are forbidden")
        match = re.fullmatch(r"      - alert: ([A-Za-z][A-Za-z0-9]+)", line)
        if match:
            current = match.group(1)
            if current in alerts:
                raise SystemExit(f"duplicate alert: {current}")
            alerts[current] = {"expr": False, "labels": False, "annotations": False, "summary": False}
            continue
        if current is None:
            continue
        for key, prefix in (
            ("expr", "        expr: "),
            ("labels", "        labels: "),
            ("annotations", "        annotations:"),
            ("summary", "          summary: "),
        ):
            if line.startswith(prefix):
                alerts[current][key] = True
    if not alerts:
        raise SystemExit("Prometheus rules contain no alerts")
    incomplete = [name for name, fields in alerts.items() if not all(fields.values())]
    if incomplete:
        raise SystemExit(f"incomplete Prometheus alerts: {', '.join(incomplete)}")
    if text.count("groups:\n") != 1 or "    rules:\n" not in text:
        raise SystemExit("Prometheus rule group envelope is malformed")
    return set(METRIC.findall(text))


def validate_dashboard() -> set[str]:
    document = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    if document.get("schemaVersion") != 39 or not document.get("title"):
        raise SystemExit("Grafana dashboard metadata is incomplete")
    panels = document.get("panels")
    if not isinstance(panels, list) or not panels:
        raise SystemExit("Grafana dashboard has no panels")
    identifiers: set[int] = set()
    expressions: list[str] = []
    for panel in panels:
        identifier = panel.get("id")
        if not isinstance(identifier, int) or identifier in identifiers:
            raise SystemExit("Grafana panel IDs must be unique integers")
        identifiers.add(identifier)
        for target in panel.get("targets", []):
            expression = target.get("expr")
            if not isinstance(expression, str) or not expression.strip():
                raise SystemExit(f"Grafana panel {identifier} has an empty expression")
            expressions.append(expression)
    return set(METRIC.findall("\n".join(expressions)))


def main() -> None:
    rules_text = RULES.read_text(encoding="utf-8")
    referenced = validate_rules(rules_text) | validate_dashboard()
    missing = sorted(referenced - implemented_metrics())
    if missing:
        raise SystemExit(f"observability assets reference unknown metrics: {', '.join(missing)}")
    asset_text = rules_text + DASHBOARD.read_text(encoding="utf-8")
    leaked = [name for name in FORBIDDEN if re.search(rf"\b(?:by|without)\s*\([^)]*\b{name}\b", asset_text)]
    if leaked:
        raise SystemExit(f"privacy-sensitive grouping labels found: {', '.join(leaked)}")
    print(f"observability assets: {len(referenced)} implemented aggregate metrics")


if __name__ == "__main__":
    main()
