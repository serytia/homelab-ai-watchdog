# homelab-ai-watchdog

**Your homelab texts you when something's wrong — and tells you *why*.**

A small Python watchdog that reads your Proxmox cluster every 15 minutes, asks an
AI model to triage what it sees, and messages you **only when something actually
matters**. No green dashboards, no 3 a.m. threshold pages — a diagnosis, not an alert.

Works with **Telegram, Discord, Slack and Microsoft Teams** (one webhook URL each,
several at once if you like).

```
┌─────────┐   API (read-only)  ┌──────────┐   snapshot   ┌────────┐   findings   ┌──────────────┐
│ Proxmox │ ─────────────────► │ watchdog │ ───────────► │ Claude │ ───────────► │ your chat app│
└─────────┘                    └──────────┘              └────────┘              └──────────────┘
                                    ▲
                             systemd timer, 15 min
```

Example message:

> 🤖 Watchdog — pve1: 1 finding(s)
>
> 🟡 Backup job failing on VM 104
>    vzdump exited 255 last night; a leftover snapshot from 07/28 is the likely cause.
>    → qm delsnapshot 104 auto-2026-07-28 (verify it's not needed first)

## Why this instead of Zabbix/Uptime Kuma alerts?

Keep your monitoring — this sits **on top** of it. Threshold alerts tell you *that*
a disk is at 92%. This tells you it's at 92% *because* Thursday's backup left a
snapshot behind, and proposes the cleanup command. It also catches trends no
threshold sees: "backup runtime doubled two nights in a row, same storage, no
failure yet" is a classic dying-disk signature.

- **Read-only by design** — the Proxmox token uses the PVEAuditor role. The agent
  proposes commands; *you* run them.
- **Allowed to stay silent** — if everything is fine it sends nothing. An agent
  that can say "nothing to report" is one you can trust when it does speak.
- **No alert fatigue** — an *ongoing* issue (that backup still failing) is
  notified once per `renotify_after_hours` (default 24 h), not on every
  15-minute tick. We learned this one the hard way.
- **Cheap, and honestly priced** — a ~10-guest lab snapshotted every 15 min
  through Claude Haiku runs on the order of **$0.30–0.50/day** (the snapshot and
  its previous version ride along on every call). Halve the timer interval to
  halve it. Cap the spend in your Anthropic console so a bug can never cost more
  than a coffee.

## Quickstart

```bash
git clone https://github.com/serytia/homelab-ai-watchdog
cd homelab-ai-watchdog
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml && chmod 600 config.yaml
# fill in config.yaml, then:
.venv/bin/python watchdog.py
```

### 1. Give it eyes — Proxmox API token (read-only)

1. Proxmox UI → Datacenter → Permissions → Users: create user `aiwatch@pve`.
2. Permissions → Add → User Permission: path `/`, user `aiwatch@pve`, role **PVEAuditor**.
3. Permissions → API Tokens: add token `aiwatch` for that user, **uncheck
   "Privilege Separation"** (the token then inherits the user's read-only role).
4. Copy the secret (shown exactly once) into `config.yaml` or `PROXMOX_TOKEN_VALUE`.

Auditor role = the agent can see everything and touch nothing.

### 2. Give it a brain — Anthropic API key

Create a key at [console.anthropic.com](https://console.anthropic.com), set a
**monthly spend limit** there, and export it as `ANTHROPIC_API_KEY` for manual
runs — **a shell export never reaches systemd or cron**; for scheduled runs put
secrets in `/etc/ai-watchdog.env` (step 4) or in `config.yaml`. Default model is
Claude Haiku (cheap, fast pattern triage). Optionally set `deep_model` to a
bigger model — it runs a second diagnosis pass **only** when the cheap pass
found something.

### 3. Give it a mouth — pick your messenger(s)

| Platform | Setup | Time |
|---|---|---|
| **Telegram** | Talk to [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token. Get your chat id from [@userinfobot](https://t.me/userinfobot). | 30 s |
| **Discord** | Channel → Settings → Integrations → Webhooks → New Webhook → copy URL. | 30 s |
| **Slack** | [api.slack.com/apps](https://api.slack.com/apps) → Create App → Incoming Webhooks → Activate → Add to channel → copy URL. | 2 min |
| **Teams** | See below — classic webhooks are gone. | 3 min |

Enable any combination in `config.yaml` — the report goes to all of them.

#### Teams: the Workflows dance (2026 edition)

Microsoft retired classic Office 365 connector webhooks (fully disabled since
May 2026). The supported path:

1. In the Teams channel: ⋯ → **Workflows** → search template
   **"Post to a channel when a webhook request is received"**.
2. Create it, pick the team + channel, and copy the generated **HTTP URL**.
3. Paste it as `workflow_url` in `config.yaml`.

The watchdog sends an Adaptive Card, which is what that trigger expects.

### 4. Give it a schedule

```bash
sudo cp -r . /opt/homelab-ai-watchdog
sudo useradd -r -s /usr/sbin/nologin aiwatch
sudo mkdir -p /opt/homelab-ai-watchdog/state
sudo chown -R aiwatch: /opt/homelab-ai-watchdog

# Secrets for the service (shell exports never reach systemd):
sudo tee /etc/ai-watchdog.env >/dev/null <<'EOF'
ANTHROPIC_API_KEY=sk-ant-...
PROXMOX_TOKEN_VALUE=...
EOF
sudo chmod 600 /etc/ai-watchdog.env

sudo cp systemd/ai-watchdog.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ai-watchdog.timer
```

Cron works too: `*/15 * * * * cd /opt/homelab-ai-watchdog && .venv/bin/python watchdog.py`
(define the two variables at the top of the crontab, or use `config.yaml`).

## Guardrails (read before deploying)

1. **Read-only token.** PVEAuditor. The agent proposes, you dispose.
2. **It messages, it never executes.** There is no code path from a finding to a
   shell command.
3. **Cap the API spend** in the Anthropic console.
4. **Your infra snapshot goes to an API.** Node names, VM names, storage usage,
   task logs — no passwords, no file contents, but metadata. If that crosses a
   line for you, the architecture points the same script at a local model
   (see Roadmap).

## Adapting to other hypervisors

`proxmox_collector.py` is the only Proxmox-specific file. Anything that can
produce a JSON snapshot of "nodes, guests, storage, recent tasks" plugs into the
same triage + notify pipeline.

## Roadmap

- **v2 — give it hands**: reply to the bot to run whitelisted, reversible actions
  (Telegram first; Slack/Teams/Discord interactivity needs real bot infra).
- Local model support (Ollama) for the zero-cloud crowd.
- Home Assistant / generic JSON collector.

## License

MIT — see [LICENSE](LICENSE).
