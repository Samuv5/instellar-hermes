# Security Middleware (HITL)

Instellar Hermes includes a three-layer security middleware that protects your system from dangerous commands executed by the AI agent.

## Architecture

```
User Request → LLM → Tool Call → terminal_tool()
                                        │
                          ┌─────────────▼──────────────┐
                          │  Hermes Guard (approval.py) │
                          │  • Hardline blocklist       │
                          │  • Dangerous patterns       │
                          └─────────────┬──────────────┘
                                        │
                          ┌─────────────▼──────────────┐
                          │  Security Middleware        │
                          │  • Static Filter            │
                          │  • Sudo Whitelist           │
                          │  • Telegram Gate            │
                          └─────────────┬──────────────┘
                                        │
                          ┌─────────────▼──────────────┐
                          │  subprocess.Popen           │
                          │  (only if all gates pass)   │
                          └────────────────────────────┘
```

## Configuration

Edit `~/.hermes/security_config.json`:

```json
{
  "enabled": true,
  "static_filter": true,
  "sudo_whitelist": true,
  "telegram_gate": true,
  "sudo_whitelist": [
    "apt update",
    "apt install",
    "systemctl restart",
    "pip install"
  ],
  "telegram_token": "YOUR_BOT_TOKEN",
  "telegram_chat_id": "YOUR_CHAT_ID",
  "timeout_seconds": 120,
  "env_skip": ["docker", "singularity", "modal", "daytona"]
}
```

## Setting Up Your Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the prompts
3. Copy the API token into `telegram_token`
4. Send a message to your new bot
5. Visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
6. Find your `chat_id` in the response and set it in `telegram_chat_id`

## How It Works

1. **Static Filter**: Commands containing `rm -rf` (bare), `chmod 777`, `dd` to `/dev/`, or `/etc/shadow` access are blocked immediately.

2. **Sudo Whitelist**: If a command uses `sudo`, the middleware extracts the actual command and checks it against the `sudo_whitelist` array. If no match is found, the command is denied.

3. **Telegram Gate**: For commands containing critical keywords (install, mv, write, sudo, rm, chmod, apt, pip, systemctl, etc.), the middleware:
   - Pauses execution
   - Sends the command to your Telegram bot with Approve/Deny buttons
   - Waits up to `timeout_seconds` for your response
   - If timeout or error → command is **denied** (fail-safe)

## Files

| File | Description |
|------|-------------|
| `tools/security_middleware.py` | The middleware implementation |
| `~/.hermes/security_config.json` | Configuration file |
| `install.sh` | Installation script |
