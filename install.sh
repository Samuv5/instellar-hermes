#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Instellar Hermes — Installation Script
# =============================================================================
# A fork of Hermes-Agent with Human-in-the-Loop (HITL) security middleware
# that protects your system via Telegram-based command approval.
# =============================================================================

REPO_URL="https://github.com/instellar-hermes/instellar-hermes"
INSTALL_DIR="${INSTELLAR_HOME:-$HOME/.instellar}"
PYTHON="${PYTHON:-python3}"
VENV_DIR="$INSTALL_DIR/venv"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       Instellar Hermes — Installation           ║${NC}"
echo -e "${BOLD}║  Fork of Hermes-Agent + HITL Security Middleware ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Check requirements ──────────────────────────────────────────────────

command -v "$PYTHON" >/dev/null 2>&1 || {
    error "Python 3 not found. Install Python >= 3.11 and try again."
    exit 1
}

PY_VERSION=$($PYTHON --version 2>&1 | grep -oP '\d+\.\d+')
if awk "BEGIN {exit !($PY_VERSION < 3.11)}"; then
    error "Python >= 3.11 required (found $PYTHON $PY_VERSION)"
    exit 1
fi

command -v git >/dev/null 2>&1 || {
    error "git is required. Install git and try again."
    exit 1
}

# ── Clone the repository ────────────────────────────────────────────────

if [ -d "$INSTALL_DIR" ]; then
    warn "Directory $INSTALL_DIR already exists."
    read -rp "  Overwrite? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
    else
        info "Using existing installation at $INSTALL_DIR"
    fi
fi

if [ ! -d "$INSTALL_DIR" ]; then
    info "Cloning Instellar Hermes..."
    git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    info "Cloned to $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── Create virtual environment ──────────────────────────────────────────

info "Creating Python virtual environment..."
"$PYTHON" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip setuptools wheel

# ── Install dependencies ────────────────────────────────────────────────

info "Installing core dependencies..."
pip install -e ".[messaging]" 2>/dev/null || pip install -e .

# If the above doesn't include python-telegram-bot, ensure it's installed
pip install python-telegram-bot 2>/dev/null || warn "python-telegram-bot not installed (Telegram gate will be unavailable)"

# ── Set up security configuration ───────────────────────────────────────

CONFIG_DIR="$HOME/.hermes"
CONFIG_FILE="$CONFIG_DIR/security_config.json"

mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_FILE" ]; then
    info "Creating security configuration template at $CONFIG_FILE..."
    cat > "$CONFIG_FILE" << 'JSONEOF'
{
  "_comment": "Instellar Hermes — Security Middleware Configuration",
  "enabled": true,
  "static_filter": true,
  "sudo_whitelist": true,
  "telegram_gate": true,
  "sudo_whitelist": [
    "apt update",
    "apt upgrade -y",
    "apt install",
    "apt remove",
    "systemctl restart",
    "systemctl start",
    "systemctl stop",
    "systemctl status",
    "systemctl enable",
    "systemctl disable",
    "systemctl daemon-reload",
    "pip install",
    "pip3 install",
    "npm install -g",
    "chown",
    "chmod",
    "mkdir -p",
    "ln -sf"
  ],
  "telegram_token": "YOUR_BOT_TOKEN_HERE",
  "telegram_chat_id": "YOUR_CHAT_ID_HERE",
  "timeout_seconds": 120,
  "env_skip": ["docker", "singularity", "modal", "daytona"]
}
JSONEOF
    info "⚠  IMPORTANT: Edit $CONFIG_FILE and set:"
    info "   - telegram_token (get one from @BotFather on Telegram)"
    info "   - telegram_chat_id (your Telegram user/group ID)"
    info "   - sudo_whitelist (commands allowed with sudo)"
else
    info "Security config already exists at $CONFIG_FILE (not overwritten)"
fi

# ── Done ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Installation Complete!                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}Instellar Hermes${NC} installed at: ${BOLD}$INSTALL_DIR${NC}"
echo ""
echo -e "  ${BOLD}Quick Start:${NC}"
echo ""
echo -e "    source $VENV_DIR/bin/activate"
echo -e "    cd $INSTALL_DIR"
echo -e "    hermes run"
echo ""
echo -e "  ${BOLD}Configuration:${NC}"
echo -e "    Edit ${BOLD}$CONFIG_FILE${NC} to set your Telegram bot credentials."
echo ""
echo -e "  ${BOLD}Features:${NC}"
echo -e "    • Static Filter: blocks rm -rf, chmod 777, dd, /etc/shadow"
echo -e "    • Sudo Whitelist: only allow specific sudo commands"
echo -e "    • Telegram Gate: approve/reject commands via Telegram bot"
echo -e "    • Fail-safe: any error → command denied"
echo ""
echo -e "  ${BOLD}Uninstall:${NC}"
echo -e "    rm -rf $INSTALL_DIR"
echo ""
