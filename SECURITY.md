# Threat model

You are about to let a Telegram bot near your hypervisor. Good — be suspicious.
Here is the honest map of what can and cannot go wrong, written for the person
whose job is to ask "so where's the backdoor?".

## No inbound surface

Everything here is **outbound-only**. The watchdog and the responder listen on
no port. They make three kinds of outbound connections: the Proxmox API
(internal), the Anthropic API (HTTPS), and Telegram long-polling (HTTPS). There
is no webhook receiver, no tunnel, no listening service to exploit. The classic
backdoor — an exposed port with a bug behind it — structurally does not exist.

## Authority lives in the hypervisor, not in this code

Assume the worst: the responder process is fully compromised (say, a malicious
dependency). What does the attacker get? Exactly what the `aiact` token allows:
`VM.PowerMgmt` on the guests you listed in the ACL — because the privilege is
**enforced by Proxmox**, not decided by this application. The watchdog token is
PVEAuditor (read-only) and the action token should be scoped per-guest:

```bash
pveum acl modify /vms/104 -user aiact@pve -role AIWatchOperator
```

Blast radius of total compromise = power actions on your demo guests. Size the
ACL to what you can tolerate losing. Additionally, the Proxmox task log gives
you an **independent audit trail**: a compromised responder can lie in its own
`audit.jsonl`, it cannot rewrite the hypervisor's history.

## The real control plane is your Telegram account

Stealing the **bot token** does not allow command injection — the Bot API cannot
forge an incoming message from you. A stolen token lets an attacker consume the
update queue (we detect the resulting 409 conflict and alert you) or impersonate
the bot *toward* you (the one-time confirm codes limit what that achieves).

Compromising **your Telegram account** (SIM swap, stolen session) is the real
prize: it grants command access — bounded by the whitelist and the ACL above.
Treat your Telegram account as a privileged credential: enable Telegram 2FA,
pin `allowed_user_ids`, and keep `allowed_vmids` minimal.

Defenses already built in: private-chat-only, one-time confirmation codes,
rate limits, startup backlog drain (no replay of commands sent while the
responder was down, independent of the system clock), audit with author.

## The AI cannot act — but it can be lied to

There is no code path from a model finding to an action. The residual risk is
**prompt injection**: guest names and task-log strings reach the model, and a
hostile string could try to shape a finding — including a booby-trapped
`suggested_action` hoping you'll paste it into a root shell.

Rule: **model-suggested commands are untrusted data.** Read them, understand
them, never pipe them into anything automated. The suggested_action field is a
diagnostic aid, not an instruction.

## Outbound data flows (the compliance question)

- **To Anthropic**: infrastructure metadata — node/guest names, resource
  percentages, task statuses. No file contents, no credentials. If that crosses
  your line, the architecture supports pointing triage at a local model.
- **Through Telegram**: alert contents. Bot chats are TLS-protected but **not
  end-to-end encrypted** — Telegram's servers see your alerts. For a homelab,
  documented trade-off. For anything corporate: use the Discord/Slack/Teams
  notifiers inside your own compliance perimeter, and keep sensitive naming out
  of alert text.

## Hygiene expected of you

- Secrets: `config.yaml` mode 600, owned by the service user; or environment
  file `/etc/ai-watchdog.env` (600, root). Rotate tokens on any doubt (shown
  on-camera tokens in our videos are revoked before publication).
- Dependencies: four, pinned with floors in `requirements.txt`. Review them.
- systemd: units ship with `NoNewPrivileges`, `ProtectSystem=strict`, dedicated
  non-login user, writable state dir only.

## Reporting

Found something? Open a GitHub issue for design discussion, or if it's
sensitive, contact the maintainer privately (profile email). No bug bounty —
just genuine gratitude and a fix.
