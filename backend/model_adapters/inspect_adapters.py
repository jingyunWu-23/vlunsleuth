from __future__ import annotations

import argparse
import json

from backend.model_adapters.registry import build_default_registry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect registered model adapters.")
    parser.add_argument("--formal-model", action="append", default=[], help="Workflow model id to select.")
    parser.add_argument("--target", action="append", default=[], help="Target vulnerability passed to LSTMAdapter.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = build_default_registry(target_vulnerabilities=args.target or None)
    selected = registry.select_for_workflow(args.formal_model)
    payload = {
        "registered_adapters": registry.describe(),
        "requested_formal_models": args.formal_model,
        "selected_adapters": [adapter.metadata() for adapter in selected],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

