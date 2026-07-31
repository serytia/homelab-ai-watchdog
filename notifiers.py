"""Send a report through Telegram, Discord, Slack and/or Teams. Send-only, webhook-based.

All four are plain HTTP POSTs — no bot frameworks, no gateways. Teams uses the
Workflows (Power Automate) webhook with an Adaptive Card payload, since classic
O365 connector webhooks were retired in May 2026.
"""

import logging

import requests

log = logging.getLogger("watchdog.notify")

TIMEOUT = 15
SEVERITY_ICONS = {"critical": "\U0001F534", "warning": "\U0001F7E1", "info": "ℹ️"}


def format_report(findings, source="homelab"):
    lines = [f"\U0001F916 Watchdog — {source}: {len(findings)} finding(s)", ""]
    for f in findings:
        icon = SEVERITY_ICONS.get(f.get("severity", "info"), "ℹ️")
        lines.append(f"{icon} {f.get('title', 'Untitled')}")
        lines.append(f"   {f.get('detail', '')}")
        if f.get("suggested_action"):
            lines.append(f"   → {f['suggested_action']}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _post(url, payload):
    resp = requests.post(url, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()


def send_telegram(cfg, text):
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    # Telegram caps messages at 4096 chars; plain text avoids Markdown escaping traps.
    _post(url, {"chat_id": cfg["chat_id"], "text": text[:4096]})


def send_discord(cfg, text):
    # allowed_mentions neutralizes a model-generated "@everyone" in a finding title.
    _post(cfg["webhook_url"], {"content": text[:2000],
                               "allowed_mentions": {"parse": []}})


def send_slack(cfg, text):
    # Slack requires &, < and > to be entity-escaped in message text.
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    _post(cfg["webhook_url"], {"text": escaped})


def send_teams(cfg, text):
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{
                    "type": "TextBlock",
                    # Adaptive Card TextBlocks swallow single newlines; double them.
                    "text": text.replace("\n", "\n\n"),
                    "wrap": True,
                }],
            },
        }],
    }
    _post(cfg["workflow_url"], card)


SENDERS = {
    "telegram": send_telegram,
    "discord": send_discord,
    "slack": send_slack,
    "teams": send_teams,
}


def _redact(message, cfg):
    """Strip tokens and webhook URLs (they are capabilities) from log output."""
    for key in ("bot_token", "webhook_url", "workflow_url"):
        secret = cfg.get(key)
        if secret:
            message = message.replace(secret, f"<{key} redacted>")
    return message


def dispatch(notifiers_cfg, text):
    """Send text through every enabled notifier. One failing sink never blocks the others.

    Returns the number of sinks that actually delivered — callers decide what
    zero means (watchdog.py refuses to advance state on it).
    """
    sent = 0
    for name, sender in SENDERS.items():
        cfg = (notifiers_cfg or {}).get(name) or {}
        if not cfg.get("enabled"):
            continue
        try:
            sender(cfg, text)
            sent += 1
            log.info("sent via %s", name)
        except Exception as exc:  # noqa: BLE001 — a broken sink must not kill the alert
            log.error("notifier %s failed: %s", name, _redact(str(exc), cfg))
    if sent == 0:
        log.warning("no notifier delivered the message — check 'enabled' flags in config")
    return sent
