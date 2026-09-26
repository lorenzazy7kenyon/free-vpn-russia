#!/usr/bin/env python3
"""Обновление подписок, конфигураций и статистики.

Процесс:
    источники -> загрузка -> парсинг -> валидация -> дедупликация ->
    проверка доступности -> фильтрация -> классификация по протоколам ->
    запись subscriptions/ и configs/ -> обновление README -> stats.json

Правила честности:
    - выводятся только реальные результаты проверок;
    - если проверенных конфигураций нет, файлы подписок содержат
      "No verified configurations available.";
    - статистика в README формируется только из реальных данных.

Env:
    CHECK_NODES=0       отключить TCP-проверку (по умолчанию включена)
    GEOIP_TOKEN=...     определять страну по IP через ipinfo.io (опционально)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate import validate_lines          # noqa: E402
from deduplicate import dedupe               # noqa: E402
from check_nodes import check_nodes, tcp_check  # noqa: E402

NO_NODES_TEXT = "No verified configurations available."
PLACEHOLDER_URLS = {"SOURCE_URL", ""}

PROTO_DIRS = {
    "vless": "vless",
    "vmess": "vless",
    "reality": "reality",
    "hysteria2": "hysteria2",
    "shadowsocks": "shadowsocks",
    "trojan": "trojan",
}
PROTO_LABEL = {
    "vless": "VLESS",
    "vmess": "VMess",
    "reality": "VLESS Reality",
    "hysteria2": "Hysteria2",
    "shadowsocks": "Shadowsocks",
    "trojan": "Trojan",
}
PROTO_FILES = ["vless", "reality", "hysteria2", "shadowsocks", "trojan"]

README_PATH = ROOT / "README.md"
STATS_BEGIN = "<!-- STATS:START -->"
STATS_END = "<!-- STATS:END -->"


def load_sources():
    path = ROOT / "sources" / "sources.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        s for s in data.get("sources", [])
        if s.get("enabled") and s.get("url") not in PLACEHOLDER_URLS
    ]


def fetch_source(url: str) -> list:
    """Загружает источник и возвращает список строк-конфигураций."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "free-vpn-russia-updater/1.0",
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    lines = [l.strip() for l in body.splitlines()]
    if not any("://" in l for l in lines):
        # вероятный base64-дамп подписки
        import base64
        try:
            padded = body.strip().replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            lines = [l.strip() for l in decoded.splitlines()]
        except Exception:  # noqa: BLE001
            pass
    return [l for l in lines
            if l and not l.startswith(("#", "//")) and "://" in l]


def classify(node: dict) -> str:
    if node["protocol"] == "vless" and node.get("security") == "reality":
        return "reality"
    return PROTO_DIRS.get(node["protocol"], node["protocol"])


def geoip_country(ip: str, token: str):
    try:
        with urllib.request.urlopen(
            f"https://ipinfo.io/{ip}/country?token={token}", timeout=10
        ) as resp:
            return resp.read().decode().strip() or "—"
    except Exception:  # noqa: BLE001
        return "—"


def enrich_country(nodes):
    token = os.environ.get("GEOIP_TOKEN", "")
    cache = {}
    for node in nodes:
        country = "—"
        if token:
            ip = node["host"]
            if ip not in cache:
                cache[ip] = geoip_country(ip, token)
            country = cache[ip]
        node["country"] = country
    return nodes


def write_subscriptions(groups: dict):
    subs_dir = ROOT / "subscriptions"
    subs_dir.mkdir(exist_ok=True)

    written = {"all": [n["url"] for n in groups.get("__all__", [])]}
    for proto in PROTO_FILES:
        written[proto] = [n["url"] for n in groups.get(proto, [])]

    for name, urls in written.items():
        content = "\n".join(urls) + "\n" if urls else NO_NODES_TEXT + "\n"
        (subs_dir / f"{name}.txt").write_text(content, encoding="utf-8")

    # configs/<proto>/verified.txt — только если есть проверенные конфиги
    for proto in PROTO_FILES:
        proto_dir = ROOT / "configs" / proto
        proto_dir.mkdir(exist_ok=True)
        verified = proto_dir / "verified.txt"
        urls = written.get(proto, [])
        if urls:
            verified.write_text("\n".join(urls) + "\n", encoding="utf-8")
        elif verified.exists():
            verified.unlink()

    return written


def render_stats(nodes, checked_date: str) -> str:
    if not nodes:
        return (
            "Пока нет проверенных конфигураций.\n\n"
            "Этот раздел обновляется автоматически после добавления источников "
            "конфигураций в [sources/](sources/). Скрипты проекта проверяют формат, "
            "доступность узлов (TCP-подключение) и задержку подключения, после чего "
            "заполняют таблицу только реальными результатами проверки."
        )

    order = {"reachable": 0, "timeout": 1, "unreachable": 2}
    nodes = sorted(
        nodes,
        key=lambda n: (order.get(n.get("check", "unreachable"), 3),
                       n.get("latency_ms") or 10**6),
    )

    lines = [
        f"Последняя проверка: **{checked_date}**",
        "",
        "| Сервер | Страна | Протокол | Задержка | Статус | Проверено |",
        "|---|---|---|---|---|---|",
    ]
    for n in nodes[:200]:
        latency = (f"{n['latency_ms']} ms"
                   if n.get("latency_ms") is not None else "—")
        lines.append(
            f"| `{n['host']}` | {n.get('country', '—')} "
            f"| {PROTO_LABEL.get(n['protocol'], n['protocol'])} "
            f"| {latency} | `{n.get('check', '—')}` | {checked_date} |"
        )

    lines += ["", "### Сводка по протоколам", "", "| Протокол | Конфигураций | Доступно |", "|---|---|---|"]
    for proto in PROTO_FILES + ["vmess"]:
        subset = [n for n in nodes if n["protocol"] == proto]
        if not subset:
            continue
        reachable = sum(1 for n in subset if n.get("check") == "reachable")
        lines.append(f"| {PROTO_LABEL.get(proto, proto)} | {len(subset)} | {reachable} |")

    reachable = sum(1 for n in nodes if n.get("check") == "reachable")
    lines += [
        "",
        f"Всего конфигураций: **{len(nodes)}**, из них доступно при последней проверке: **{reachable}**.",
        "",
        "> Статусы: `reachable` — TCP-подключение успешно; `timeout` — превышено время ожидания; "
        "`unreachable` — подключение не удалось. Результаты фиксируются на момент проверки.",
    ]
    return "\n".join(lines)


def update_readme(nodes, checked_date: str):
    text = README_PATH.read_text(encoding="utf-8")
    start = text.index(STATS_BEGIN) + len(STATS_BEGIN)
    end = text.index(STATS_END)
    text = text[:start] + "\n" + render_stats(nodes, checked_date) + "\n" + text[end:]
    README_PATH.write_text(text, encoding="utf-8")


def main() -> int:
    checked_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sources = load_sources()
    print(f"источников включено: {len(sources)}")

    raw_lines = []
    for src in sources:
        try:
            lines = fetch_source(src["url"])
            raw_lines.extend(lines)
            print(f"  {src['name']}: {len(lines)} строк")
        except Exception as exc:  # noqa: BLE001
            print(f"  {src['name']}: ошибка загрузки ({exc})")

    nodes = [n for n in validate_lines(raw_lines)]
    valid = [n for n in nodes if n.get("valid")]
    print(f"валидных конфигураций: {len(valid)} из {len(nodes)}")

    valid = dedupe(valid)
    print(f"после дедупликации: {len(valid)}")

    if os.environ.get("CHECK_NODES", "1") != "0" and valid:
        for n in valid:
            status, latency = tcp_check(n["host"], n["port"], timeout=5.0)
            n["check"] = status
            n["latency_ms"] = latency
        print("проверка доступности выполнена")
    else:
        for n in valid:
            n["check"] = "unreachable"
            n["latency_ms"] = None
        print("проверка доступности пропущена")

    valid = enrich_country(valid)

    groups = {"__all__": valid}
    for n in valid:
        groups.setdefault(classify(n), []).append(n)

    written = write_subscriptions(groups)
    print("файлов подписок обновлено:", ", ".join(
        f"{k}={len(v)}" for k, v in written.items()))

    stats = {
        "last_update": checked_date,
        "total": len(valid),
        "by_protocol": {
            p: len(groups.get(p, [])) for p in PROTO_FILES + ["vmess"]
        },
        "by_status": {
            s: sum(1 for n in valid if n.get("check") == s)
            for s in ("reachable", "unreachable", "timeout")
        },
    }
    (ROOT / "subscriptions" / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    update_readme(valid, checked_date)
    print("README обновлён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
