#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from agent_workflow_scan.pipeline import run_scan  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static security scanner for company-internal Dify workflow DSL files.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a Dify workflow DSL")
    scan.add_argument("--dsl", required=True, type=Path, help="Internal Dify YAML/JSON export")
    scan.add_argument("--samples", type=Path, help="JSON file containing a samples array")
    scan.add_argument("--baseline", type=Path, default=SCRIPT_DIR.parent / "config" / "internal-baseline.yml")
    scan.add_argument("--rules", type=Path, default=SCRIPT_DIR.parent / "rules" / "core-rules.yml")
    scan.add_argument("--waivers", type=Path, help="Optional audited YAML/JSON waiver file")
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument("--llm", choices=("disabled", "auto", "enabled"), default="auto")
    scan.add_argument("--analyst-model", default="gpt-5.6-terra")
    scan.add_argument("--reviewer-model", default="gpt-5.6-sol")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command != "scan":
        return 2
    try:
        result = run_scan(
            dsl_path=args.dsl,
            samples_path=args.samples,
            baseline_path=args.baseline if args.baseline.exists() else None,
            output_dir=args.output,
            rules_path=args.rules,
            waivers_path=args.waivers if args.waivers and args.waivers.exists() else None,
            llm_mode=args.llm,
            analyst_model=args.analyst_model,
            reviewer_model=args.reviewer_model,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return int(result.get("exit_code", 2))
    except Exception as error:
        print(json.dumps({"error": str(error), "type": type(error).__name__}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
