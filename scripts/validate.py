#!/usr/bin/env python3
"""Валидация share-ссылок VPN-конфигураций.

Поддерживаемые схемы:
    vless://              VLESS (включая Reality: security=reality)
    vmess://              VMess (base64 JSON)
    trojan://             Trojan
    ss://                 Shadowsocks
    hysteria2://, hy2://  Hysteria2

Статус формата: valid | invalid

CLI:
    python3 validate.py links.txt
    cat links.txt | python3 validate.py

Вывод: JSON-список узлов со статусом и найденными ошибками.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from urllib.parse import parse_qs, unquote, urlparse

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.I,
)
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-cfb", "aes-256-cfb", "rc4-md5", "none",
}

SCHEME_TO_PROTOCOL = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
}


def _b64decode(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value)


def _is_ipv4(host: str) -> bool:
    if not IPV4_RE.match(host):
        return False
    return all(0 <= int(p) <= 255 for p in host.split("."))


def _host_port_errors(host: str, port) -> list:
    errors = []
    host = (host or "").strip().strip("[]")
    if not host:
        errors.append("пустой host")
    elif not (HOSTNAME_RE.match(host) or _is_ipv4(host) or ":" in host):
        errors.append(f"некорректный host: {host}")
    try:
        port_int = int(str(port).strip())
        if not (0 < port_int < 65536):
            errors.append(f"некорректный port: {port}")
    except (TypeError, ValueError):
        errors.append(f"некорректный port: {port}")
    return errors


def _base_node(url: str, protocol: str) -> dict:
    parsed = urlparse(url)
    return {
        "url": url,
        "protocol": protocol,
        "host": (parsed.hostname or "").strip().strip("[]"),
        "port": parsed.port,
        "name": unquote(parsed.fragment) if parsed.fragment else "",
        "params": {k: v[0] for k, v in parse_qs(parsed.query).items()},
        "errors": [],
    }


def parse_vless(url: str) -> dict:
    node = _base_node(url, "vless")
    parsed = urlparse(url)
    uuid = unquote(parsed.username or "")
    node["credential"] = uuid
    if not UUID_RE.match(uuid):
        node["errors"].append("некорректный UUID")
    node["errors"] += _host_port_errors(node["host"], node["port"])

    params = node["params"]
    if params.get("encryption") not in (None, "none"):
        node["errors"].append("encryption для VLESS должен быть none")
    security = params.get("security", "none")
    node["security"] = security
    if security == "reality":
        pbk = params.get("pbk", "")
        if not REALITY_PBK_RE.match(pbk):
            node["errors"].append(
                "некорректный pbk для Reality (ожидается 43 символа base64url)"
            )
        if not params.get("sni"):
            node["errors"].append("для Reality обязателен параметр sni")
        sid = params.get("sid", "")
        if sid and not re.match(r"^[0-9a-f]{1,16}$", sid, re.I):
            node["errors"].append(f"некорректный sid для Reality: {sid}")
    flow = params.get("flow", "")
    if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-direct"):
        node["errors"].append(f"неизвестный flow: {flow}")
    return node


def parse_vmess(url: str) -> dict:
    try:
        payload = json.loads(_b64decode(url[len("vmess://"):]).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        node = _base_node(url, "vmess")
        node["errors"].append(f"не удалось декодировать vmess JSON: {exc}")
        return node

    node = _base_node(url, "vmess")
    node["host"] = str(payload.get("add", "")).strip()
    node["port"] = payload.get("port")
    node["name"] = str(payload.get("ps", ""))
    node["credential"] = str(payload.get("id", ""))
    node["security"] = payload.get("scy") or payload.get("security") or "auto"
    node["params"] = {
        "net": payload.get("net", "tcp"),
        "tls": payload.get("tls", ""),
        "sni": payload.get("sni", ""),
        "path": payload.get("path", ""),
        "host": payload.get("host", ""),
    }
    if not UUID_RE.match(node["credential"]):
        node["errors"].append("некорректный UUID в поле id")
    node["errors"] += _host_port_errors(node["host"], node["port"])
    return node


def parse_trojan(url: str) -> dict:
    node = _base_node(url, "trojan")
    parsed = urlparse(url)
    password = unquote(parsed.username or "")
    node["credential"] = password
    if not password:
        node["errors"].append("пустой пароль")
    node["errors"] += _host_port_errors(node["host"], node["port"])
    if node["params"].get("security", "tls") not in ("tls", "none", ""):
        node["errors"].append("для Trojan допустим security=tls")
    return node


def parse_shadowsocks(url: str) -> dict:
    node = _base_node(url, "shadowsocks")
    body = url[len("ss://"):]
    userinfo, _, hostport = body.partition("@")
    hostport = hostport.split("/")[0].split("?")[0]

    try:
        decoded = _b64decode(userinfo).decode("utf-8")
        if "@" in decoded:  # формат 2022: base64(method:password)@host:port
            userinfo, hostport = decoded.rsplit("@", 1)
            hostport = hostport.split("/")[0].split("?")[0]
        else:
            userinfo = decoded
        method, _, password = userinfo.partition(":")
    except Exception:  # noqa: BLE001
        method, _, password = unquote(userinfo).partition(":")

    node["credential"] = password
    node["params"] = {"method": method}
    if not password:
        node["errors"].append("пустой пароль")
    if method not in SS_METHODS:
        node["errors"].append(f"неизвестный метод шифрования: {method}")
    node["errors"] += _host_port_errors(node["host"], node["port"])
    return node


def parse_hysteria2(url: str) -> dict:
    node = _base_node(url, "hysteria2")
    parsed = urlparse(url)
    node["credential"] = unquote(parsed.username or "")
    node["errors"] += _host_port_errors(node["host"], node["port"])
    if node["params"].get("obfs") and not node["params"].get("obfs-password"):
        node["errors"].append("obfs указан без obfs-password")
    return node


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
}


def validate_line(line: str):
    """Валидирует одну строку-конфигурацию. Возвращает dict или None."""
    line = line.strip()
    if not line or line.startswith(("#", "//")):
        return None
    scheme = line.split("://", 1)[0].lower()
    parser = PARSERS.get(scheme)
    if parser is None:
        return {
            "url": line,
            "protocol": "unknown",
            "host": "",
            "port": None,
            "name": "",
            "params": {},
            "errors": [f"неподдерживаемая схема: {scheme or 'пусто'}"],
        }
    node = parser(line)
    node["valid"] = not node["errors"]
    return node


def validate_lines(lines):
    """Валидирует список строк, возвращает список узлов."""
    return [n for n in (validate_line(l) for l in lines) if n is not None]


def main() -> int:
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as fh:
            lines = fh.readlines()
    else:
        lines = sys.stdin.readlines()

    nodes = validate_lines(lines)
    print(json.dumps(nodes, ensure_ascii=False, indent=2))
    valid = sum(1 for n in nodes if n.get("valid"))
    print(f"total: {len(nodes)}, valid: {valid}, invalid: {len(nodes) - valid}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
