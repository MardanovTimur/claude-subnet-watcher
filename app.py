#!/usr/bin/env python3
"""
Claude IP Subnets Monitor & HTTP Server for OpenWrt Podkop + Telegram Bot.
Zero external dependencies (Python standard library only).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("claude-ip-bot")


def load_dotenv(dotenv_path: Path) -> None:
    """Load simple KEY=VALUE pairs from .env file if it exists."""
    if not dotenv_path.is_file():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DOCS_MD_URL = os.environ.get(
    "CLAUDE_DOCS_URL", "https://platform.claude.com/docs/en/api/ip-addresses.md"
)
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
CHECK_INTERVAL_SEC = int(os.environ.get("CHECK_INTERVAL_SEC", "1800"))  # 30 minutes default
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
STATE_FILE = DATA_DIR / "state.json"

CIDR_CANDIDATE_RE = re.compile(r"([0-9a-fA-F:.]+/\d{1,3})")


def extract_valid_cidrs(text: str) -> tuple[list[str], list[str]]:
    """Extract and validate IPv4 and IPv6 CIDRs from text, preserving order."""
    v4: list[str] = []
    v6: list[str] = []
    for match in CIDR_CANDIDATE_RE.findall(text):
        try:
            net = ipaddress.ip_network(match, strict=False)
            norm = str(net)
            if isinstance(net, ipaddress.IPv4Network):
                if norm not in v4:
                    v4.append(norm)
            else:
                if norm not in v6:
                    v6.append(norm)
        except ValueError:
            continue
    return v4, v6


def collapse_ipv4_cidrs(cidrs: list[str]) -> list[str]:
    """Collapse overlapping IPv4 networks into minimal supernets."""
    nets = [ipaddress.IPv4Network(c, strict=False) for c in cidrs]
    collapsed = ipaddress.collapse_addresses(nets)
    return [str(n) for n in collapsed]


def parse_claude_ip_markdown(md_text: str) -> dict[str, Any]:
    """
    Parse Claude IP addresses markdown into structured categories:
    - inbound_ipv4
    - outbound_ipv4
    - all_ipv4 (unique union of inbound + outbound IPv4)
    - collapsed_ipv4 (minimal supernets covering inbound + outbound IPv4)
    - ipv6 (active inbound/outbound IPv6)
    - phased_out (deprecated CIDRs, ignored in active lists)
    """
    inbound_v4: list[str] = []
    outbound_v4: list[str] = []
    active_v6: list[str] = []
    phased_out: list[str] = []

    current_h2 = ""
    current_h3 = ""

    for line in md_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            current_h2 = stripped[3:].strip().lower()
            current_h3 = ""
            continue
        if stripped.startswith("### "):
            current_h3 = stripped[4:].strip().lower()
            continue

        v4_list, v6_list = extract_valid_cidrs(stripped)
        if not v4_list and not v6_list:
            continue

        if "phased out" in current_h3 or "phased out" in current_h2:
            for c in v4_list + v6_list:
                if c not in phased_out:
                    phased_out.append(c)
        elif "inbound" in current_h2:
            for c in v4_list:
                if c not in inbound_v4:
                    inbound_v4.append(c)
            for c in v6_list:
                if c not in active_v6:
                    active_v6.append(c)
        elif "outbound" in current_h2:
            for c in v4_list:
                if c not in outbound_v4:
                    outbound_v4.append(c)
            for c in v6_list:
                if c not in active_v6:
                    active_v6.append(c)

    all_v4: list[str] = []
    for c in inbound_v4 + outbound_v4:
        if c not in all_v4:
            all_v4.append(c)

    collapsed_v4 = collapse_ipv4_cidrs(all_v4) if all_v4 else []

    if not all_v4 and not active_v6:
        raise ValueError("No active IP subnets found in document (possible format change)")

    return {
        "inbound_ipv4": inbound_v4,
        "outbound_ipv4": outbound_v4,
        "all_ipv4": all_v4,
        "collapsed_ipv4": collapsed_v4,
        "ipv6": active_v6,
        "phased_out": phased_out,
    }


def fetch_markdown(url: str = DOCS_MD_URL, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "claude-podkop-ip-monitor/1.0 (+https://github.com)",
            "Accept": "text/markdown, text/plain, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


class SubnetStore:
    """Thread-safe store for parsed subnets and persistence."""

    def __init__(self, data_dir: Path, state_file: Path) -> None:
        self.data_dir = data_dir
        self.state_file = state_file
        self.lock = threading.Lock()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state: dict[str, Any] = self._load_initial_state()

    def _load_initial_state(self) -> dict[str, Any]:
        if self.state_file.is_file():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                logger.info("Loaded existing state from %s", self.state_file)
                return data
            except Exception as exc:
                logger.warning("Failed to read state file %s: %s", self.state_file, exc)
        return {
            "inbound_ipv4": [],
            "outbound_ipv4": [],
            "all_ipv4": [],
            "collapsed_ipv4": [],
            "ipv6": [],
            "phased_out": [],
            "updated_at": None,
            "last_checked_at": None,
            "last_error": None,
        }

    def write_text_files(self, data: dict[str, Any]) -> None:
        """Write static .txt files into data_dir as well."""
        files_map = {
            "inbound.txt": data.get("inbound_ipv4", []),
            "outbound.txt": data.get("outbound_ipv4", []),
            "all.txt": data.get("all_ipv4", []),
            "supernets.txt": data.get("collapsed_ipv4", []),
            "ipv6.txt": data.get("ipv6", []),
            "all-with-ipv6.txt": data.get("all_ipv4", []) + data.get("ipv6", []),
        }
        for filename, lines in files_map.items():
            path = self.data_dir / filename
            content = "\n".join(lines) + ("\n" if lines else "")
            path.write_text(content, encoding="utf-8")

    def refresh(self) -> tuple[bool, dict[str, Any], dict[str, dict[str, list[str]]]]:
        """
        Fetch and parse markdown from Anthropic docs.
        Returns (changed, current_state, diff_report).
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            md_text = fetch_markdown()
            parsed = parse_claude_ip_markdown(md_text)
        except Exception as exc:
            with self.lock:
                self.state["last_checked_at"] = now_iso
                self.state["last_error"] = str(exc)
                self.state_file.write_text(
                    json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            raise

        with self.lock:
            is_first_load = self.state.get("updated_at") is None
            diff: dict[str, dict[str, list[str]]] = {}
            tracked_keys = ("inbound_ipv4", "outbound_ipv4", "all_ipv4", "ipv6", "phased_out")
            changed = False

            for key in tracked_keys:
                old_set = set(self.state.get(key, []))
                new_set = set(parsed.get(key, []))
                added = [x for x in parsed.get(key, []) if x not in old_set]
                removed = [x for x in self.state.get(key, []) if x not in new_set]
                if added or removed:
                    diff[key] = {"added": added, "removed": removed}
                    if key != "phased_out":
                        changed = True

            self.state.update(parsed)
            self.state["last_checked_at"] = now_iso
            self.state["last_error"] = None
            if changed or is_first_load:
                self.state["updated_at"] = now_iso

            self.state_file.write_text(
                json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            self.write_text_files(self.state)

            return (changed and not is_first_load), dict(self.state), diff

    def get_snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)


class TelegramNotifier:
    """Minimal Telegram Bot client using standard urllib (notifications + commands)."""

    def __init__(self, token: str, default_chat_id: str, store: SubnetStore) -> None:
        self.token = token
        self.default_chat_id = str(default_chat_id).strip() if default_chat_id else ""
        self.store = store
        self.api_base = f"https://api.telegram.org/bot{self.token}" if self.token else ""

    @property
    def enabled(self) -> bool:
        return bool(self.token)

    def send_message(self, text: str, chat_id: str | None = None) -> bool:
        target_chat = chat_id or self.default_chat_id
        if not self.enabled or not target_chat:
            return False
        url = f"{self.api_base}/sendMessage"
        payload = json.dumps(
            {
                "chat_id": target_chat,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 200
        except Exception as exc:
            logger.error("Failed to send Telegram message: %s", exc)
            return False

    def format_status_message(self, state: dict[str, Any], header: str = "📊 <b>Текущие подсети Claude (Anthropic)</b>") -> str:
        inbound = "\n".join(f"• <code>{c}</code>" for c in state.get("inbound_ipv4", [])) or "—"
        outbound = "\n".join(f"• <code>{c}</code>" for c in state.get("outbound_ipv4", [])) or "—"
        supernets = "\n".join(f"• <code>{c}</code>" for c in state.get("collapsed_ipv4", [])) or "—"
        ipv6 = "\n".join(f"• <code>{c}</code>" for c in state.get("ipv6", [])) or "—"
        updated = state.get("updated_at") or "—"
        checked = state.get("last_checked_at") or "—"

        return (
            f"{header}\n\n"
            f"<b>Inbound IPv4:</b>\n{inbound}\n\n"
            f"<b>Outbound IPv4:</b>\n{outbound}\n\n"
            f"<b>Суперсети IPv4 (collapsed):</b>\n{supernets}\n\n"
            f"<b>IPv6:</b>\n{ipv6}\n\n"
            f"🕒 Изменено: <code>{updated}</code>\n"
            f"🔄 Проверено: <code>{checked}</code>\n"
            f"🔗 <a href=\"{DOCS_MD_URL}\">Источник документации</a>"
        )

    def format_diff_alert(
        self, state: dict[str, Any], diff: dict[str, dict[str, list[str]]]
    ) -> str:
        lines = ["🚨 <b>Обнаружены изменения IP-подсетей Claude!</b>\n"]
        labels = {
            "inbound_ipv4": "Inbound IPv4",
            "outbound_ipv4": "Outbound IPv4",
            "ipv6": "IPv6",
            "phased_out": "Phased Out (устаревшие)",
        }
        for key, label in labels.items():
            if key not in diff:
                continue
            added = diff[key].get("added", [])
            removed = diff[key].get("removed", [])
            lines.append(f"<b>{label}:</b>")
            for c in added:
                lines.append(f"  ➕ <code>{c}</code>")
            for c in removed:
                lines.append(f"  ➖ <code>{c}</code>")
            lines.append("")

        lines.append(self.format_status_message(state, header="📋 <b>Актуальный список сейчас:</b>"))
        return "\n".join(lines)

    def poll_updates_forever(self, stop_event: threading.Event) -> None:
        if not self.enabled:
            return
        logger.info("Telegram bot polling started (commands: /start, /status, /check, /urls)")
        offset = 0
        while not stop_event.is_set():
            try:
                url = f"{self.api_base}/getUpdates?timeout=25&offset={offset}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                if not data.get("ok"):
                    time.sleep(5)
                    continue
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = (
                        upd.get("message")
                        or upd.get("edited_message")
                        or upd.get("channel_post")
                        or upd.get("edited_channel_post")
                    )
                    if not msg:
                        continue
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    text = (msg.get("text") or "").strip()
                    if not text.startswith("/"):
                        continue
                    self._handle_command(chat_id, text)
            except urllib.error.URLError:
                time.sleep(5)
            except Exception as exc:
                logger.warning("Telegram polling error: %s", exc)
                time.sleep(5)

    def _handle_command(self, chat_id: str, text: str) -> None:
        # Restrict commands to TG_CHAT_ID if configured
        if self.default_chat_id and chat_id != self.default_chat_id:
            logger.warning("Ignored command from unauthorized chat_id=%s", chat_id)
            return

        cmd = text.split()[0].split("@")[0].lower()
        if cmd in ("/start", "/help"):
            help_msg = (
                "👋 <b>Бот мониторинга подсетей Claude для Podkop</b>\n\n"
                f"Ваш <code>TG_CHAT_ID</code>: <code>{chat_id}</code>\n\n"
                "<b>Доступные команды:</b>\n"
                "/status — показать текущие подсети в кэше\n"
                "/check — принудительно запросить документацию Anthropic прямо сейчас\n"
                "/urls — показать HTTP-эндпоинты для вставки в Podkop"
            )
            self.send_message(help_msg, chat_id=chat_id)
        elif cmd == "/status":
            snap = self.store.get_snapshot()
            self.send_message(self.format_status_message(snap), chat_id=chat_id)
        elif cmd == "/check":
            try:
                changed, snap, diff = self.store.refresh()
                if changed:
                    self.send_message(self.format_diff_alert(snap, diff), chat_id=chat_id)
                else:
                    self.send_message(
                        self.format_status_message(
                            snap, header="✅ <b>Проверка выполнена: изменений нет</b>"
                        ),
                        chat_id=chat_id,
                    )
            except Exception as exc:
                self.send_message(
                    f"❌ <b>Ошибка при проверке документации:</b>\n<code>{exc}</code>",
                    chat_id=chat_id,
                )
        elif cmd == "/urls":
            base_url = os.environ.get("PUBLIC_BASE_URL", "https://pl.mardanoff.ru/claude").rstrip("/")
            urls_msg = (
                "🌐 <b>HTTPS-эндпоинты для Podkop (Remote Subnet List):</b>\n\n"
                f"• <code>{base_url}/supernets.txt</code> — агрегированные суперсети IPv4 (<b>рекомендуется для Podkop</b>)\n"
                f"• <code>{base_url}/inbound.txt</code> — только Inbound IPv4 (/23, /22)\n"
                f"• <code>{base_url}/outbound.txt</code> — Outbound IPv4 (/21, /20)\n"
                f"• <code>{base_url}/all.txt</code> — все IPv4 (Inbound + Outbound)\n"
                f"• <code>{base_url}/ipv6.txt</code> — только IPv6 (/48)\n"
                f"• <code>{base_url}/state.json</code> — полный JSON статус"
            )
            self.send_message(urls_msg, chat_id=chat_id)


def make_http_handler(store: SubnetStore):
    class SubnetHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed_path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
            snap = store.get_snapshot()

            routes_txt: dict[str, list[str]] = {
                "/inbound.txt": snap.get("inbound_ipv4", []),
                "/outbound.txt": snap.get("outbound_ipv4", []),
                "/all.txt": snap.get("all_ipv4", []),
                "/claude-ips.txt": snap.get("all_ipv4", []),
                "/supernets.txt": snap.get("collapsed_ipv4", []),
                "/ipv6.txt": snap.get("ipv6", []),
                "/all-with-ipv6.txt": snap.get("all_ipv4", []) + snap.get("ipv6", []),
            }

            if parsed_path in routes_txt:
                lines = routes_txt[parsed_path]
                body = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed_path in ("/status.json", "/health"):
                body = json.dumps(snap, indent=2, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed_path == "/":
                index_lines = [
                    "Claude Podkop Subnet Server",
                    "===========================",
                    "",
                    "Available endpoints for Podkop:",
                    "  /inbound.txt       - Inbound IPv4 subnets (160.79.104.0/23, 153.61.224.0/22)",
                    "  /outbound.txt      - Outbound IPv4 subnets (160.79.104.0/21, 153.61.208.0/20)",
                    "  /all.txt           - All active IPv4 subnets (Inbound + Outbound)",
                    "  /supernets.txt     - Collapsed minimal IPv4 supernets (recommended)",
                    "  /ipv6.txt          - Active IPv6 subnets (2607:6bc0::/48)",
                    "  /all-with-ipv6.txt - All active IPv4 + IPv6 subnets",
                    "  /status.json       - Full JSON state & metadata",
                    "",
                    f"Last updated: {snap.get('updated_at')}",
                    f"Last checked: {snap.get('last_checked_at')}",
                ]
                body = ("\n".join(index_lines) + "\n").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_Error_404()

        def send_Error_404(self) -> None:
            body = b"404 Not Found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.info("HTTP %s - %s", self.address_string(), fmt % args)

    return SubnetHTTPRequestHandler


def periodic_check_loop(
    store: SubnetStore, notifier: TelegramNotifier, interval: int, stop_event: threading.Event
) -> None:
    while not stop_event.wait(interval):
        try:
            changed, snap, diff = store.refresh()
            logger.info("Periodic check OK (changed=%s)", changed)
            if changed:
                notifier.send_message(notifier.format_diff_alert(snap, diff))
        except Exception as exc:
            logger.error("Periodic check failed: %s", exc)


def main() -> None:
    once_mode = "--once" in sys.argv
    store = SubnetStore(DATA_DIR, STATE_FILE)
    notifier = TelegramNotifier(TG_BOT_TOKEN, TG_CHAT_ID, store)

    try:
        changed, snap, diff = store.refresh()
        logger.info(
            "Initial sync complete: inbound=%s, outbound=%s, ipv6=%s",
            snap["inbound_ipv4"],
            snap["outbound_ipv4"],
            snap["ipv6"],
        )
        if changed:
            notifier.send_message(notifier.format_diff_alert(snap, diff))
    except Exception as exc:
        logger.error("Initial sync failed (using cached state if available): %s", exc)

    if once_mode:
        print(json.dumps(store.get_snapshot(), indent=2, ensure_ascii=False))
        return

    stop_event = threading.Event()

    def handle_sig(signum: int, _frame: Any) -> None:
        logger.info("Received signal %s, shutting down...", signum)
        stop_event.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    httpd = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), make_http_handler(store))
    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    checker_thread = threading.Thread(
        target=periodic_check_loop,
        args=(store, notifier, CHECK_INTERVAL_SEC, stop_event),
        daemon=True,
    )
    checker_thread.start()

    if notifier.enabled:
        tg_thread = threading.Thread(
            target=notifier.poll_updates_forever, args=(stop_event,), daemon=True
        )
        tg_thread.start()
    else:
        logger.info("TG_BOT_TOKEN is not set; running in HTTP-only mode without Telegram bot.")

    logger.info("Listening on http://%s:%d (interval=%ds)", HTTP_HOST, HTTP_PORT, CHECK_INTERVAL_SEC)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
