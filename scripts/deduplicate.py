#!/usr/bin/env python3
"""Удаление дубликатов конфигураций.

Ключ дедупликации по умолчанию: (протокол, host, port, credential).
С флагом --endpoint: (протокол, host, port) — убирает несколько конфигураций
на одном и том же адресе.

Учитываются только конфигурации с valid=true.

CLI:
    python3 validate.py links.txt | python3 deduplicate.py
    python3 deduplicate.py report.json --endpoint
"""
from __future__ import annotations

import argparse
import json
import sys


def dedupe(nodes, by_endpoint: bool = False):
    seen = set()
    unique = []
    for node in nodes:
        if not node.get("valid"):
            continue
        if by_endpoint:
            key = (node["protocol"], node["host"], node["port"])
        else:
            key = (node["protocol"], node["host"], node["port"],
                   node.get("credential", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique


def main() -> int:
    ap = argparse.ArgumentParser(description="Дедупликация конфигураций")
    ap.add_argument("input", nargs="?", help="JSON-файл с узлами (иначе stdin)")
    ap.add_argument("--endpoint", action="store_true",
                    help="дедуплицировать по (протокол, host, port)")
    args = ap.parse_args()

    raw = open(args.input, encoding="utf-8").read() if args.input else sys.stdin.read()
    nodes = json.loads(raw)

    unique = dedupe(nodes, by_endpoint=args.endpoint)
    print(json.dumps(unique, ensure_ascii=False, indent=2))
    print(f"before: {sum(1 for n in nodes if n.get('valid'))}, after: {len(unique)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
