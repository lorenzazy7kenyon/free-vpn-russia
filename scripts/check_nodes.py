#!/usr/bin/env python3
"""Базовая проверка доступности узлов через TCP-подключение.

Вход: JSON-список узлов из validate.py.
Выход: тот же список + поля:
    check       reachable | unreachable | timeout
    latency_ms  задержка TCP-подключения в миллисекундах (или null)

CLI:
    python3 validate.py links.txt | python3 check_nodes.py
    python3 check_nodes.py report.json --timeout 5 --workers 50
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
import time


def tcp_check(host: str, port, timeout: float = 5.0):
    """TCP-подключение. Возвращает (status, latency_ms)."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            latency = int((time.monotonic() - start) * 1000)
            return "reachable", latency
    except socket.timeout:
        return "timeout", None
    except OSError:
        return "unreachable", None
    except (TypeError, ValueError):
        return "unreachable", None


def check_nodes(nodes, timeout: float = 5.0, workers: int = 50):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(tcp_check, n["host"], n["port"], timeout): n
            for n in nodes
            if n.get("valid")
        }
        for future in concurrent.futures.as_completed(futures):
            node = futures[future]
            status, latency = future.result()
            node["check"] = status
            node["latency_ms"] = latency
    for node in nodes:
        node.setdefault("check", "unreachable")
        node.setdefault("latency_ms", None)
    return nodes


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP-проверка доступности узлов")
    ap.add_argument("input", nargs="?", help="JSON-файл с узлами (иначе stdin)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--workers", type=int, default=50)
    args = ap.parse_args()

    raw = open(args.input, encoding="utf-8").read() if args.input else sys.stdin.read()
    nodes = json.loads(raw)

    check_nodes(nodes, timeout=args.timeout, workers=args.workers)
    print(json.dumps(nodes, ensure_ascii=False, indent=2))

    summary = {}
    for n in nodes:
        if n.get("valid"):
            summary[n["check"]] = summary.get(n["check"], 0) + 1
    print(f"checked: {summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
