"""
Instellar Security Middleware — Human-in-the-Loop (HITL) for shell execution.

Layers (applied in order):
  1. Static Filter    — block rm -rf (bare), chmod 777, dd, /etc/shadow
  2. Sudo Whitelist   — only allow sudo commands in a local JSON whitelist
  3. Telegram Gate    — pause, send to Telegram bot, wait for Approve/Deny

Fail-safe: any error/exception → DENY (command does NOT run).
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _get_config_path() -> Path:
    """Return path to security_config.json (inside HERMES_HOME or ~/.hermes)."""
    try:
        from hermes_constants import get_hermes_home
        return get_hermes_home() / "security_config.json"
    except Exception:
        return Path.home() / ".hermes" / "security_config.json"


def _get_config() -> dict:
    """Load security_config.json. Returns {} on any error (fail-safe)."""
    path = _get_config_path()
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load %s: %s", path, exc)
    return {}


# ---------------------------------------------------------------------------
# STATIC FILTER — commands that are NEVER allowed
# ---------------------------------------------------------------------------

_STATIC_BLOCK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # rm -rf without a specific path → nuke everything
    (re.compile(r'\brm\s+(-[rfv]+\s+)*(-rf\s+)?/?\s*($|[;&|])', re.I | re.DOTALL),
     "rm -rf with no explicit safe path"),
    # chmod 777 — world-writable
    (re.compile(r'\bchmod\s+(-[^\s]*\s+)*777\b', re.I),
     "chmod 777 (world-writable)"),
    # dd to raw block device
    (re.compile(r'\bdd\b[^\n]*\bof=\s*/dev/', re.I),
     "dd to /dev/ block device"),
    # /etc/shadow read/write
    (re.compile(r'(?:^|[;&|`\n])\s*(?:sudo\s+)?(?:cat|nano|vim?|echo|>|>>|tee)\s+/etc/shadow', re.I),
     "access to /etc/shadow"),
    # Direct rm -rf /
    (re.compile(r'\brm\s+(-[^\s]*\s+)*-rf\s+(/\s*\*?\s*$|/\s+)/?\s*($|[;&|])', re.I),
     "rm -rf / (filesystem destruction)"),
]

# 'Critical' command keywords that require Telegram approval
_CRITICAL_KEYWORDS = re.compile(
    r'\b(install|uninstall|mv|write|sudo|rm|chmod|chown|'
    r'dd|mkfs|mount|umount|fdisk|parted|'
    r'apt|apt-get|dpkg|pip|pip3|npm|brew|'
    r'cargo|gem|composer|'
    r'systemctl|service|initctl|'
    r'>\s*[^&\s]|>>\s*[^&\s]|tee\s)',
    re.I
)


def check_static_filter(command: str) -> tuple[bool, str]:
    """Check command against static blocklist.

    Returns:
        (is_blocked: bool, reason: str)
    """
    for pattern, desc in _STATIC_BLOCK_PATTERNS:
        if pattern.search(command):
            return True, desc
    return False, ""


# ---------------------------------------------------------------------------
# SUDO WHITELIST
# ---------------------------------------------------------------------------

def _parse_sudo_command(command: str) -> str | None:
    """Extract the actual command after sudo. Returns None if no sudo."""
    m = re.match(r'^\s*sudo\s+(.+)$', command, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def check_sudo_whitelist(command: str, config: dict) -> tuple[bool, str]:
    """Check if a sudo command is in the whitelist.

    Returns:
        (is_blocked: bool, reason: str)
    """
    sudo_cmd = _parse_sudo_command(command)
    if sudo_cmd is None:
        return False, ""  # not a sudo command

    whitelist: list[str] = config.get("sudo_whitelist", [])
    if not whitelist:
        return True, "sudo command not in whitelist (whitelist is empty)"

    # Match: any whitelist entry that is a prefix of the sudo command
    sudo_cmd_lower = sudo_cmd.lower()
    for entry in whitelist:
        entry_lower = entry.lower().strip()
        if sudo_cmd_lower.startswith(entry_lower):
            return False, ""
    return True, f"sudo command not in whitelist: {sudo_cmd[:100]}"


def is_critical_command(command: str) -> bool:
    """Return True if the command contains critical keywords."""
    return bool(_CRITICAL_KEYWORDS.search(command))


# ---------------------------------------------------------------------------
# TELEGRAM GATE (using python-telegram-bot)
# ---------------------------------------------------------------------------

class TelegramGate:
    """Send approval requests to Telegram and wait for Approve/Deny.

    Runs the bot's asyncio event loop in a background daemon thread.
    Fail-safe: any error or timeout → denies the command.
    """

    def __init__(self, token: str, chat_id: str | int, timeout: int = 120):
        self.token = token
        self.chat_id = str(chat_id) if not isinstance(chat_id, str) else chat_id
        self.timeout = timeout

        self._loop: asyncio.AbstractEventLoop | None = None
        self._bot = None
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    # ------------------------------------------------------------------
    # Background thread: runs the asyncio event loop
    # ------------------------------------------------------------------

    def _run(self):
        """Entry point for the daemon thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
            from telegram.request import HTTPXRequest

            req = HTTPXRequest(connection_pool_size=1)
            self._bot = Bot(self.token, request=req)
            self._ready.set()
            self._loop.run_until_complete(self._poll())
        except Exception as exc:
            logger.error("TelegramGate thread failed: %s", exc)
        finally:
            self._running = False

    async def _poll(self):
        """Long-poll loop for callback queries."""
        offset = 0
        while self._running:
            try:
                from telegram.error import TelegramError
                updates = await self._bot.get_updates(
                    offset=offset,
                    timeout=30,
                    allowed_updates=["callback_query"],
                )
                for update in updates:
                    offset = update.update_id + 1
                    await self._handle_update(update)
            except (TelegramError, Exception):
                await asyncio.sleep(1)

    async def _handle_update(self, update):
        """Process a callback query (Approve/Deny button press)."""
        query = update.callback_query
        msg_id = str(query.message.message_id)
        data = query.data  # "approve" or "deny"

        with self._lock:
            entry = self._pending.get(msg_id)
            if entry:
                entry["result"] = data
                entry["event"].set()

        try:
            text = "✅ Approved" if data == "approve" else "❌ Denied"
            await query.answer(text=text)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Start the polling thread. Safe to call multiple times."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def stop(self):
        """Stop the polling thread."""
        self._running = False

    def request_approval(self, command: str) -> tuple[bool, str]:
        """Send approval request, block until response.

        Returns:
            (approved: bool, detail: str)
        """
        if not self._bot or not self._running:
            return False, "Telegram bot not initialized"

        from telegram import InlineKeyboardButton, InlineKeyboardMarkup

        async def _send():
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✅ Approve", callback_data="approve"),
                    InlineKeyboardButton("❌ Deny", callback_data="deny"),
                ]
            ])
            # Escape text for safe sending (strip markdown-sensitive chars)
            safe_cmd = command[:500].replace("_", " ").replace("*", " ").replace("`", " ").replace("[", "(")
            msg = await self._bot.send_message(
                chat_id=self.chat_id,
                text=(
                    "🔒 *Security Approval Required*\n\n"
                    f"Command:\n`{safe_cmd}`\n\n"
                    "_Approve or deny this command:_"
                ),
                parse_mode="Markdown",
                reply_markup=keyboard,
            )
            return str(msg.message_id)

        try:
            future = asyncio.run_coroutine_threadsafe(_send(), self._loop)
            msg_id = future.result(timeout=15)
        except Exception as exc:
            return False, f"send failed: {exc}"

        event = threading.Event()
        with self._lock:
            self._pending[msg_id] = {"event": event, "result": None}

        try:
            ok = event.wait(timeout=self.timeout)
        finally:
            with self._lock:
                entry = self._pending.pop(msg_id, {})
                result = entry.get("result", "deny")

        if not ok:
            return False, f"timeout ({self.timeout}s) — auto-denied"

        return result == "approve", f"user {result}"


# ---------------------------------------------------------------------------
# SECURITY GATE — orchestrates all layers
# ---------------------------------------------------------------------------

_gate_instance = None
_gate_lock = threading.Lock()


class SecurityGate:
    """Orchestrates all security layers for command validation.

    Usage:
        gate = SecurityGate()
        result = gate.validate("rm -rf /tmp/test")
        if not result["approved"]:
            print(result["reason"])
    """

    def __init__(self):
        self._config = _get_config()
        self._telegram: TelegramGate | None = None
        self._telegram_initialized = False

        # Config values
        self.enabled = self._config.get("enabled", True)
        self.static_filter = self._config.get("static_filter", True)
        self.sudo_whitelist_enabled = self._config.get("sudo_whitelist", True)
        self.telegram_enabled = self._config.get("telegram_gate", True)
        self.telegram_timeout = self._config.get("timeout_seconds", 120)
        self.telegram_token = self._config.get("telegram_token", "")
        self.telegram_chat_id = self._config.get("telegram_chat_id", "")
        self.env_skip = self._config.get("env_skip", ["docker", "singularity", "modal", "daytona"])

    def _init_telegram(self):
        """Lazy-init Telegram bot."""
        if self._telegram_initialized:
            return
        with _gate_lock:
            if self._telegram_initialized:
                return
            self._telegram_initialized = True
            if not self.telegram_token or not self.telegram_chat_id:
                logger.warning("SecurityGate: telegram gate disabled — missing token or chat_id")
                return
            try:
                gate = TelegramGate(self.telegram_token, self.telegram_chat_id, self.telegram_timeout)
                gate.start()
                self._telegram = gate
            except Exception as exc:
                logger.error("SecurityGate: failed to init Telegram: %s", exc)

    def validate(self, command: str, env_type: str = "") -> dict:
        """Validate a command through all security layers.

        Args:
            command: The shell command string.
            env_type: Environment type (docker, local, etc.) for env skipping.

        Returns:
            {"approved": True/False, "reason": str, "layer": str}
        """
        # Global enable/disable
        if not self.enabled:
            return {"approved": True, "reason": "middleware disabled", "layer": "config"}

        # Skip for container environments (they can't damage host)
        if env_type in self.env_skip:
            return {"approved": True, "reason": f"skipped for {env_type}", "layer": "env_skip"}

        # ── Layer 1: Static Filter ──────────────────────────────────────
        if self.static_filter:
            blocked, reason = check_static_filter(command)
            if blocked:
                logger.warning("SecurityGate STATIC BLOCK: %s — cmd: %.200s", reason, command)
                return {"approved": False, "reason": f"Static filter: {reason}", "layer": "static"}

        # ── Layer 2: Sudo Whitelist ─────────────────────────────────────
        if self.sudo_whitelist_enabled:
            blocked, reason = check_sudo_whitelist(command, self._config)
            if blocked:
                logger.warning("SecurityGate SUDO BLOCK: %s — cmd: %.200s", reason, command)
                return {"approved": False, "reason": f"Sudo whitelist: {reason}", "layer": "sudo"}

        # ── Layer 3: Telegram Approval Gate ─────────────────────────────
        if self.telegram_enabled and is_critical_command(command):
            self._init_telegram()
            if self._telegram is None:
                # Telegram gate desired but unavailable → DENY (fail-safe)
                return {
                    "approved": False,
                    "reason": "Telegram gate required but not configured (set telegram_token and telegram_chat_id in security_config.json)",
                    "layer": "telegram",
                }
            approved, detail = self._telegram.request_approval(command)
            if not approved:
                logger.warning("SecurityGate TELEGRAM DENY: %s — cmd: %.200s", detail, command)
                return {"approved": False, "reason": f"Telegram: {detail}", "layer": "telegram"}
            logger.info("SecurityGate TELEGRAM APPROVE: %s — cmd: %.200s", detail, command)

        return {"approved": True, "reason": "passed", "layer": ""}


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def get_gate() -> SecurityGate:
    """Return the singleton SecurityGate instance."""
    global _gate_instance
    if _gate_instance is None:
        with _gate_lock:
            if _gate_instance is None:
                _gate_instance = SecurityGate()
    return _gate_instance


def validate_command(command: str, env_type: str = "") -> dict:
    """One-shot command validation using the singleton gate."""
    return get_gate().validate(command, env_type=env_type)
