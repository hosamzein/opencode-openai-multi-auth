# opencode-openai-multi-auth

OpenCode plugin that adds Antigravity-style multi-account rotation for the `openai` provider.

## Features

- Stores multiple OpenAI OAuth accounts in `~/.config/opencode/openai-accounts.json`
- Runs account rotation on rate-limit (`429`, `503`, `529`)
- Supports:
  - `sticky` strategy
  - `round-robin` strategy
- Optional `pid_offset_enabled` for parallel processes

## Configure

Add plugin in `~/.config/opencode/opencode.json`:

```json
{
  "plugin": [
    "opencode-openai-multi-auth",
    "opencode-pty"
  ]
}
```

Optional plugin config file `~/.config/opencode/openai-multi.json`:

```json
{
  "account_selection_strategy": "sticky",
  "pid_offset_enabled": true,
  "rate_limit_cooldown_seconds": 60
}
```

## Add Accounts

Run multiple times:

```bash
opencode auth login openai
```

Each successful login is merged into `openai-accounts.json`.
