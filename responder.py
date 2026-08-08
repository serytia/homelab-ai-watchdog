#!/usr/bin/env python3
"""homelab-ai-watchdog responder: give the watchdog hands — carefully.

Long-running Telegram command loop. Security model, in order of importance:
- Commands are only obeyed in YOUR private chat (chat_id + chat.type=private,
  optionally pinned to specific user ids); strangers are counted, never echoed.
- Actions use a SEPARATE Proxmox token with a narrow role (VM.PowerMgmt) that
  you scope per-guest with ACLs — the watchdog's auditor token stays read-only.
- The action catalog is hardcoded: no configurable shell templates, ever.
- State-changing commands are armed with a one-time nonce, need
  "/confirm <nonce>" within a timeout, are rate-limited, and are audited
  BEFORE the result is announced.
- On startup the whole Telegram backlog is drained and acked without being
  executed (clock-independent), so a restart never replays commands typed
  while the responder was down.

TELEGRAM_API_BASE (env) overrides the Telegram endpoint — used by the offline
test suite only; do not set it in production.
"""

import json
import logging
import os
import secrets
import sys
import time
from pathlib import Path

import requests
import yaml

import proxmox_collector
import triage as triage_mod

log = logging.getLogger("responder")

TELEGRAM_API = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org")
MAX_MESSAGE_AGE_S = 120
# Telegram counts UTF-16 units with a 4096 cap; 3500 python chars stays safe.
MAX_SAY_CHARS = 3500

HELP_TEXT = (
    "🤖 Homelab Watchdog — commands:\n"
    "/status — cluster summary (read-only)\n"
    "/check — run an AI triage now (read-only)\n"
    "/vmstart <vmid> — start an allowed guest\n"
    "/vmshutdown <vmid> — graceful shutdown of an allowed guest\n"
    "/confirm <code> — approve the pending action\n"
    "/help — this message\n"
    "Actions need a second confirmation and are rate-limited."
)


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    for section in ("proxmox", "triage", "notifiers", "responder"):
        cfg[section] = cfg.get(section) or {}
    if os.environ.get("PROXMOX_TOKEN_VALUE"):
        cfg["proxmox"]["token_value"] = os.environ["PROXMOX_TOKEN_VALUE"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cfg["triage"]["api_key"] = os.environ["ANTHROPIC_API_KEY"]
    if os.environ.get("PROXMOX_ACTION_TOKEN_VALUE"):
        cfg["responder"]["action_token_value"] = os.environ["PROXMOX_ACTION_TOKEN_VALUE"]
    return cfg


class Responder:
    def __init__(self, cfg):
        self.cfg = cfg
        tg = cfg["notifiers"].get("telegram") or {}
        if not tg.get("enabled"):
            raise SystemExit("responder requires notifiers.telegram.enabled: true")
        if not tg.get("bot_token") or not tg.get("chat_id"):
            raise SystemExit("responder needs notifiers.telegram bot_token + chat_id")
        self.token = tg["bot_token"]
        self.chat_id = str(tg["chat_id"])
        r = cfg["responder"]
        self.allowed_vmids = {int(v) for v in (r.get("allowed_vmids") or [])}
        self.allowed_user_ids = {str(u) for u in (r.get("allowed_user_ids") or [])}
        self.max_per_hour = int(r.get("max_actions_per_hour", 6))
        self.max_readonly_per_min = int(r.get("max_readonly_per_min", 4))
        self.confirm_timeout = int(r.get("confirm_timeout_s", 60))
        self.state_dir = Path(cfg.get("state_file", "state/last_snapshot.json")).parent
        self.offset_file = self.state_dir / "responder.offset"
        self.audit_file = self.state_dir / "audit.jsonl"
        self.pending = None            # {"label", "func", "expires", "nonce"}
        self.action_times = []         # executed actions (rolling hour)
        self.readonly_times = []       # read-only commands (rolling minute)
        self.stranger_count = 0
        self.stranger_last_report = 0.0

    # ------------------------------------------------------------------ redact
    def _redact(self, text):
        text = str(text)
        for secret_val in (self.token,
                           self.cfg["responder"].get("action_token_value"),
                           self.cfg["proxmox"].get("token_value"),
                           self.cfg["triage"].get("api_key")):
            if secret_val:
                text = text.replace(secret_val, "<redacted>")
        return text

    # ---------------------------------------------------------------- telegram
    def api(self, method, **params):
        r = requests.post(f"{TELEGRAM_API}/bot{self.token}/{method}",
                          json=params, timeout=70)
        r.raise_for_status()
        return r.json()

    def say(self, text):
        try:
            self.api("sendMessage", chat_id=self.chat_id,
                     text=self._redact(text)[:MAX_SAY_CHARS])
        except requests.RequestException as exc:
            log.warning("sendMessage failed: %s", self._redact(exc))

    # ------------------------------------------------------------------- audit
    def audit(self, command, outcome, sender=""):
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            entry = {"ts": time.time(), "from": sender,
                     "command": command, "outcome": self._redact(outcome)}
            with open(self.audit_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            log.error("audit write FAILED (%s -> %s): %s", command, outcome, exc)
        log.info("audit: %s -> %s", command, self._redact(outcome))

    # ----------------------------------------------------------------- proxmox
    def action_client(self):
        r = self.cfg["responder"]
        if not r.get("action_token_value"):
            return None
        px_cfg = dict(self.cfg["proxmox"])
        px_cfg["user"] = r.get("action_user", "aiact@pve")
        px_cfg["token_name"] = r.get("action_token_name", "aiact")
        px_cfg["token_value"] = r["action_token_value"]
        return proxmox_collector.connect(px_cfg)

    def find_guest(self, vmid):
        """Return (node, kind, status) for a qemu VM or lxc container."""
        px = proxmox_collector.connect(self.cfg["proxmox"])  # read-only lookup
        for node in px.nodes.get():
            if node.get("status") != "online":
                continue
            for kind in ("qemu", "lxc"):
                for guest in getattr(px.nodes(node["node"]), kind).get():
                    if int(guest.get("vmid", -1)) == vmid:
                        return node["node"], kind, guest.get("status")
        return None, None, None

    # ------------------------------------------------------------- rate guards
    def guard_readonly(self):
        now = time.time()
        self.readonly_times = [t for t in self.readonly_times if now - t < 60]
        if len(self.readonly_times) >= self.max_readonly_per_min:
            return f"⛔ Rate limit: {self.max_readonly_per_min} read commands/minute."
        self.readonly_times.append(now)
        return None

    def guard_action(self, vmid):
        if not self.cfg["responder"].get("action_token_value"):
            return "⛔ No action token configured — I'm running read-only."
        if vmid not in self.allowed_vmids:
            return (f"⛔ Guest {vmid} is not in allowed_vmids. The whitelist is "
                    "the point: add it in config.yaml if you really mean it.")
        now = time.time()
        self.action_times = [t for t in self.action_times if now - t < 3600]
        if len(self.action_times) >= self.max_per_hour:
            return f"⛔ Rate limit: {self.max_per_hour} actions/hour reached."
        return None

    # ---------------------------------------------------------------- commands
    def cmd_status(self):
        err = self.guard_readonly()
        if err:
            self.say(err)
            return
        snap = proxmox_collector.collect(self.cfg["proxmox"])
        lines = ["📊 Cluster status:"]
        for n in snap["nodes"]:
            lines.append(f"  node {n['node']}: {n['status']}, cpu {n.get('cpu_pct')}%, "
                         f"mem {n.get('mem_pct')}%, rootfs {n.get('rootfs_pct')}%")
        running = sum(1 for g in snap["guests"] if g["status"] == "running")
        lines.append(f"  guests: {running}/{len(snap['guests'])} running")
        failed = [t for t in snap["recent_tasks"]
                  if t.get("status") not in (None, "OK", "RUNNING")]
        lines.append(f"  recent failed tasks: {len(failed)}")
        self.say("\n".join(lines))

    def cmd_check(self):
        err = self.guard_readonly()
        if err:
            self.say(err)
            return
        self.say("🔎 Running a triage check…")
        snap = proxmox_collector.collect(self.cfg["proxmox"])
        findings = triage_mod.triage(self.cfg["triage"], snap, None)
        if not findings:
            self.say("✅ Nothing to report.")
            return
        import notifiers
        self.say(notifiers.format_report(
            findings, source=self.cfg["proxmox"].get("host", "pve")))

    def request_action(self, label, func, sender):
        if self.pending and time.time() <= self.pending["expires"]:
            self.say(f"⛔ An action is already pending: {self.pending['label']}. "
                     "Confirm it or let it expire first.")
            self.audit(label, "refused: another action pending", sender)
            return
        nonce = secrets.token_hex(2)
        self.pending = {"label": label, "func": func, "nonce": nonce,
                        "expires": time.time() + self.confirm_timeout}
        self.audit(label, f"armed (nonce {nonce})", sender)
        self.say(f"⚠️ Pending: {label}\nReply /confirm {nonce} within "
                 f"{self.confirm_timeout}s to execute.")

    def _action_command(self, vmid, verb, wanted_status, sender):
        err = self.guard_action(vmid)
        if err:
            self.say(err)
            self.audit(f"{verb} {vmid}", f"refused: {err[:60]}", sender)
            return
        node, kind, status = self.find_guest(vmid)
        if node is None:
            self.say(f"⛔ Guest {vmid} not found on any online node.")
            return
        if status == wanted_status:
            self.say(f"ℹ️ Guest {vmid} is already {wanted_status}.")
            return

        def do():
            client = self.action_client()
            endpoint = getattr(client.nodes(node), kind)(vmid).status
            getattr(endpoint, verb).post()
            return f"✅ {verb} requested for {kind} {vmid} on {node}."
        self.request_action(f"{verb} {kind} {vmid} on {node}", do, sender)

    def cmd_confirm(self, nonce, sender):
        if not self.pending:
            self.say("Nothing pending.")
            return
        label, func = self.pending["label"], self.pending["func"]
        if time.time() > self.pending["expires"]:
            self.pending = None
            self.say("⌛ Pending action expired — ask again.")
            self.audit(label, "expired", sender)
            return
        if nonce != self.pending["nonce"]:
            self.say(f"⛔ Wrong code. Expected: /confirm {self.pending['nonce']} "
                     f"(action: {label}).")
            self.audit(label, "confirm rejected: wrong nonce", sender)
            return
        self.pending = None
        try:
            result = func()
        except Exception as exc:  # noqa: BLE001 — report, never crash the loop
            self.audit(label, f"error: {exc}", sender)
            self.say(f"❌ Action failed: {exc}")
            return
        self.action_times.append(time.time())
        # Audit BEFORE announcing: an executed action must exist on disk even
        # if Telegram is down at this exact moment.
        self.audit(label, "executed", sender)
        self.say(result)

    # ------------------------------------------------------------------- loop
    def handle(self, message):
        chat = str(message.get("chat", {}).get("id", ""))
        chat_type = message.get("chat", {}).get("type", "")
        sender = str(message.get("from", {}).get("id", ""))
        text = (message.get("text") or "").strip()

        if chat != self.chat_id or chat_type != "private" or (
                self.allowed_user_ids and sender not in self.allowed_user_ids):
            # Never echo attacker-controlled content; aggregate, 1 report/hour.
            log.warning("ignored message from chat=%s type=%s from=%s",
                        chat, chat_type, sender)
            self.stranger_count += 1
            now = time.time()
            if now - self.stranger_last_report >= 3600:
                self.stranger_last_report = now
                self.say(f"🚨 Ignored {self.stranger_count} message(s) from "
                         "unauthorized chats since last report.")
                self.stranger_count = 0
            return
        if time.time() - message.get("date", 0) > MAX_MESSAGE_AGE_S:
            log.info("ignored stale command: %r", text[:60])
            return

        parts = text.split()
        cmd = parts[0].lower().split("@")[0] if parts else ""

        def vmid_arg():
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return None

        try:
            if cmd == "/status":
                self.cmd_status()
            elif cmd == "/check":
                self.cmd_check()
            elif cmd == "/vmstart" and vmid_arg() is not None:
                self._action_command(vmid_arg(), "start", "running", sender)
            elif cmd == "/vmshutdown" and vmid_arg() is not None:
                self._action_command(vmid_arg(), "shutdown", "stopped", sender)
            elif cmd == "/confirm":
                self.cmd_confirm(parts[1] if len(parts) == 2 else None, sender)
            elif cmd in ("/help", "/start"):
                self.say(HELP_TEXT)
            elif cmd:
                self.say("Unknown command — /help")
        except Exception as exc:  # noqa: BLE001 — one bad command must not kill the loop
            log.error("command %r failed: %s", text[:60], self._redact(exc))
            self.say(f"❌ Error: {exc}")

    def load_offset(self):
        try:
            return int(self.offset_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            return 0

    def save_offset(self, offset):
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self.offset_file.write_text(str(offset), encoding="utf-8")
        except OSError as exc:
            log.error("cannot persist offset %s: %s", offset, exc)

    def drain_backlog(self, offset):
        """Ack every update queued while we were down, executing none of them.

        Deliberately clock-independent: wall-clock deltas fail open when the
        host reboots with a late clock. A restart must never replay commands
        typed into the void.
        """
        dropped = 0
        while True:
            resp = self.api("getUpdates", offset=offset, timeout=0)
            batch = resp.get("result", [])
            if not batch:
                break
            for update in batch:
                offset = update["update_id"] + 1
                dropped += 1
            self.save_offset(offset)
        if dropped:
            self.say(f"♻️ Restarted — ignored {dropped} queued message(s) sent "
                     "while I was down. Resend your command if still wanted.")
        return offset

    def run(self):
        offset = self.drain_backlog(self.load_offset())
        conflict_streak = 0
        log.info("responder up (chat ***%s, %d allowed guests, actions %s)",
                 self.chat_id[-3:], len(self.allowed_vmids),
                 "ON" if self.cfg["responder"].get("action_token_value") else "read-only")
        while True:
            try:
                resp = self.api("getUpdates", offset=offset, timeout=50)
                conflict_streak = 0
                for update in resp.get("result", []):
                    offset = update["update_id"] + 1
                    self.save_offset(offset)
                    if "message" in update:
                        self.handle(update["message"])
            except requests.HTTPError as exc:
                code = exc.response.status_code if exc.response is not None else 0
                if code == 409:
                    # Another getUpdates consumer holds the token. One stray 409
                    # after a restart is normal; a streak means a second instance
                    # is silently stealing the command channel.
                    conflict_streak += 1
                    if conflict_streak == 5:
                        log.error("persistent 409: another responder instance "
                                  "is polling this bot token")
                        self.say("🚨 Command channel conflict: another process is "
                                 "polling this bot. Commands may be lost.")
                    time.sleep(min(60, 5 * conflict_streak))
                else:
                    log.warning("telegram HTTP %s, retrying in 10s: %s",
                                code, self._redact(exc))
                    time.sleep(10)
            except requests.RequestException as exc:
                log.warning("telegram poll error, retrying in 10s: %s",
                            self._redact(exc))
                time.sleep(10)
            except Exception as exc:  # noqa: BLE001 — the loop must survive anything
                log.error("unexpected error in poll loop: %s", self._redact(exc))
                time.sleep(5)


def main():
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(config_path)
    if not cfg["responder"].get("enabled"):
        raise SystemExit("responder.enabled is false in config — nothing to do")
    Responder(cfg).run()


if __name__ == "__main__":
    main()
